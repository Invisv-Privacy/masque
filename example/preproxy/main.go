package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"strings"
	"syscall"

	masque "github.com/invisv-privacy/masque"
	masqueH3 "github.com/invisv-privacy/masque/http3"
	"github.com/quic-go/quic-go"
)

// A port list to be used as a default if one is not provided via a file.
// These are the ports that preproxy should listen on.
var PortListBase = []int{
	80, 443, 5349, 7880,
}
var PortListBaseTcp = []int{
	7881,
}
var PortListBaseUdp = []int{
	7882,
}

var insecure *bool

// This port range is to allow a large number of UDP ports to be added.
// This is useful when a client may use an unknown high port number.
const PortRangeUdpMin = 50000
const PortRangeUdpMax = 60000

var logger *slog.Logger

// Assemble the default port list using the global + constant values defined above.
// This returns a TCP and UDP port list.
func defaultPortList() ([]int, []int) {
	var portListTCP []int = []int{}
	var portListUDP []int = []int{}
	portListTCP = append(portListTCP, PortListBase...)
	portListUDP = append(portListUDP, PortListBase...)
	portListTCP = append(portListTCP, PortListBaseTcp...)
	portListUDP = append(portListUDP, PortListBaseUdp...)
	for i := PortRangeUdpMin; i <= PortRangeUdpMax; i++ {
		portListUDP = append(portListUDP, i)
	}
	return portListTCP, portListUDP
}

// loadPortFile loads the provided port file. It returns a list of TCP and UDP
// ports to forward.  The format of the file is tcp:port_number or
// udp:port_number on individual lines.
//
// TODO: Support port ranges in the form of udp:port_start-port_end
func loadPortFile(portFile string) ([]int, []int, error) {
	portList, err := os.ReadFile(portFile)
	if err != nil {
		return nil, nil, err
	}

	var portListTCP []int = []int{}
	var portListUDP []int = []int{}
	for _, line := range strings.Split(string(portList), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("line %s in port file is invalid", line)
		}

		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, nil, fmt.Errorf("line %s in port file has an invalid port %s",
				line, parts[1])
		}
		if strings.Compare(parts[0], "tcp") == 0 {
			portListTCP = append(portListTCP, port)
		} else if strings.Compare(parts[0], "udp") == 0 {
			portListUDP = append(portListUDP, port)
		} else {
			return nil, nil, fmt.Errorf("line %s in port file has an invalid network %s",
				line, parts[0])
		}
	}

	return portListTCP, portListUDP, nil
}

// Starts running the preproxy on localaddr by tunneling connections thru the given proxyaddr
// to the final destination targetServer for the ports configured (either by default or via the portconf file).
func main() {
	invisvRelay := flag.String("invisvRelay", "", "Invisv Relay Server")
	invisvRelayPort := flag.String("invisvRelayPort", "443", "Invisv Relay Server Port")
	targetServer := flag.String("targetServer", "", "Target server to proxy all connections to")

	localAddr := flag.String("localaddr", "127.0.0.1", "Local address to listen on")
	token := flag.String("token", "", "Invisv Relay authentication token")
	certDataFile := flag.String("certDataFile", "", "Cert file to load and use. If none provided, cert checking will be disabled")
	insecure = flag.Bool("insecure", false, "Ignore check of Relay server certificate?")
	verbose := flag.Bool("verbose", false, "Whether to log at DEBUG level")
	mtu := flag.Int("mtu", 1500, "MTU (affects UDP only)")
	portFile := flag.String("portconf", "", "Text file with ports in net:port format (e.g. tcp:443, udp:7882)")
	pprofEnabled := flag.Bool("pprof", false, "Enable the pprof profiling/debugging server")

	flag.Parse()

	if *targetServer == "" {
		flag.Usage()
		log.Fatal("targetServer flag is required")
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}

	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	if *pprofEnabled {
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}

	var err error
	var certData []byte

	if *certDataFile != "" {
		certData, err = os.ReadFile(*certDataFile)
		if err != nil {
			log.Fatal(err)
		}
		*insecure = false
	}

	var portListTCP, portListUDP []int
	if *portFile == "" {
		portListTCP, portListUDP = defaultPortList()
	} else {
		portListTCP, portListUDP, err = loadPortFile(*portFile)
		if err != nil {
			log.Fatal(err)
		}
	}

	rlimit := &syscall.Rlimit{}
	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, rlimit)
	if err != nil {
		log.Fatal(err)
	}
	numNeededFds := uint64((PortRangeUdpMax - PortRangeUdpMin) +
		len(PortListBase) + len(PortListBaseUdp) +
		len(PortListBaseTcp))
	if rlimit.Max < numNeededFds {
		log.Fatal(fmt.Errorf("FD rlimit value %d is below the required needed value of %d", rlimit.Max, numNeededFds))
	} else if rlimit.Cur < numNeededFds {
		rlimit.Cur = rlimit.Max
		err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, rlimit)
		if err != nil {
			log.Fatal(err)
		}
	}

	proxy := *invisvRelay + ":" + *invisvRelayPort

	config := masqueH3.ClientConfig{
		ProxyAddr: proxy,
		AuthToken: *token,
		Insecure:  *insecure,
		CertData:  certData,
		Logger:    logger,
	}

	relayClient, err := masqueH3.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	logger = logger.With("ProxyAddr", proxy)

	for _, port := range portListTCP {
		host := *localAddr + ":" + strconv.Itoa(port)
		l, err := net.Listen("tcp", host)
		if err != nil {
			log.Fatal(err)
		}
		logger.Info("Listening on tcp", "host", host)
		go func(port int, l net.Listener) {
			target := *targetServer + ":" + strconv.Itoa(port)
			for {
				c, err := l.Accept()
				if err != nil {
					logger.Error("Couldn't accept client connection", "err", err)
					continue
				}
				logger.Info("Accepted TCP client connection from", "RemoteAddr", c.RemoteAddr())
				masqueConn, err := HandleConnectMasque(relayClient, c, target, true, func(c net.Conn) {})
				if err != nil {
					logger.Error("Failed to open masque connection", "err", err)
					if err := c.Close(); err != nil {
						logger.Error("Failed to close masque connection", "err", err)
					}

				} else {
					logger.Debug("Opened TCP masque connection for client", "c.LocalAddr", c.LocalAddr(), "c.RemoteAddr", c.RemoteAddr())
					go Transfer(masqueConn, c)
					go Transfer(c, masqueConn)
				}
			}
		}(port, l)
	}
	for _, port := range portListUDP {
		host := *localAddr + ":" + strconv.Itoa(port)
		l, err := net.ListenPacket("udp", host)
		if err != nil {
			log.Fatal(err)
		}
		logger.Info("Listening on udp", "host", host)
		go func(port int, l net.PacketConn) {
			var buf []byte = make([]byte, *mtu)
			target := *targetServer + ":" + strconv.Itoa(port)
			udpConns := make(map[string]io.ReadWriteCloser)
			for {
				logger.Debug("ReadingFrom UDP")
				n, addr, err := l.ReadFrom(buf[:])
				if err != nil {
					logger.Error("Couldn't read from client connection", "err", err)
					continue
				}
				logger.Debug("ReadFrom UDP", "addr", addr, "n", n)
				masqueConn, ok := udpConns[addr.String()]
				if !ok {
					masqueConn, err = HandleConnectMasque(relayClient, nil, target, false, func(c net.Conn) {})
					if err != nil {
						logger.Error("Couldn't connect to target server", "target", target, "port", port, "addr", addr, "err", err)
						continue
					} else {
						logger.Debug("Opened UDP masque connection for client", "addr", addr)
						udpConns[addr.String()] = masqueConn
						go func(udpConns map[string]io.ReadWriteCloser, addr net.Addr, masqueConn io.ReadWriteCloser) {
							var bufFromMasque []byte = make([]byte, *mtu)
							for {
								logger.Debug("Reading from UDP masque connection for client", "addr", addr)
								n, err := masqueConn.Read(bufFromMasque[:])
								if err != nil {
									logger.Error("Couldn't read from masque connection", "err", err)
									delete(udpConns, addr.String())
									if err := masqueConn.Close(); err != nil {
										logger.Error("Failed to close masque connection", "err", err)
									}
									break
								}
								logger.Debug("Writing bytes to client over UDP", "n", n, "addr", addr)
								_, err = l.WriteTo(bufFromMasque[:n], addr)
								if err != nil {
									logger.Error("Couldn't write to client connection", "err", err)
									delete(udpConns, addr.String())
									if err := masqueConn.Close(); err != nil {
										logger.Error("Failed to close masque connection", "err", err)
									}
									break
								}
							}
						}(udpConns, addr, masqueConn)
					}
				}
				n, err = masqueConn.Write(buf[:n])
				if err != nil {
					tooLargeError, ok := err.(*quic.DatagramTooLargeError)
					if ok {
						logger.Error("Couldn't write to masque connection, DatagramTooLargeError", "err", err, "peerMax", tooLargeError.PeerMaxDatagramFrameSize, "n", n)
					} else {
						logger.Error("Couldn't write to masque connection, ", "err", err)
					}
					delete(udpConns, addr.String())
				} else {
					logger.Debug("Wrote UDP to masqueConn", "n", n)
				}
			}
		}(port, l)
	}
	// Wait forever.
	select {}
}

// Transfer copies data from src to dst and closes both when done.
func Transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer func() {
		if err := dst.Close(); err != nil {
			logger.Error("Failed to close dst", "err", err)
		}
	}()

	defer func() {
		if err := src.Close(); err != nil {
			logger.Error("Failed to close src", "err", err)
		}
	}()
	_, err := io.Copy(dst, src)
	if err != nil {
		logger.Error("Failed to copy", "err", err)
	}
}

// A connFailFunc is called when a Relay stream creation fails. It is given the
// connection being proxied so it can reply to the client if needed.
type connFailFunc func(c net.Conn)

// HandleConnectMasque creates a new TCP or UDP stream via the relayClient and
// returns the connected stream upon success.
func HandleConnectMasque(relayClient *masqueH3.Client, c net.Conn, target string, isTcp bool, fail connFailFunc) (io.ReadWriteCloser, error) {
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		logger.Error("Failed to split host and port", "err", err)
		fail(c)
		if err := c.Close(); err != nil {
			logger.Error("Failed to close c", "err", err)
		}
		return nil, err
	}

	portInt, err := strconv.Atoi(port)
	if err != nil {
		logger.Error("Failed to convert port to int", "err", err)
		fail(c)
		if err := c.Close(); err != nil {
			logger.Error("Failed to close c", "err", err)
		}
		return nil, err
	}

	if masque.IsDisallowedPort(uint16(portInt)) {
		logger.Error("Disallowed port", "port", port)
		fail(c)
		if err := c.Close(); err != nil {
			logger.Error("Failed to close c", "err", err)
		}
		return nil, fmt.Errorf("Disallowed port: %s", port)
	}

	var masqueConn io.ReadWriteCloser
	if isTcp {
		masqueConn, err = relayClient.CreateTCPStream(target)
		if err != nil {
			logger.Error("Failed to create TCP stream", "err", err)
			fail(c)
			if err := c.Close(); err != nil {
				logger.Error("Failed to close c", "err", err)
			}
			return nil, err
		}
	} else {
		masqueConn, err = relayClient.CreateUDPStream(target)
		if err != nil {
			logger.Error("Failed to create UDP stream", "err", err)
			fail(c)
			if err := c.Close(); err != nil {
				logger.Error("Failed to close c", "err", err)
			}
			return nil, err
		}
	}

	return masqueConn, nil
}
