// relay-http-proxy is a sample application that uses the INVISV IETF MASQUE
// stack.  It listens on a local port, presenting an ordinary HTTP proxy
// interface, and sends requests it receives to the destination host via the
// MASQUE relay server, such as the one run by INVISV. In effect, this tunnels
// ordinary HTTP via MASQUE (which is itself an extension to HTTP).
package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	masque "github.com/invisv-privacy/masque"
	masqueH2 "github.com/invisv-privacy/masque/http2"
)

// Command line flags
var listenPort *int       // Port to listen on for HTTP CONNECT requests
var listenStatusPort *int // Port to listen on for proxy status requests
var auth *string          // Authentication for proxy access, in format username:password
var invisvRelay *string   // Invisv Relay server to connect to
var invisvRelayPort *int  // Invisv Relay server port to connect to
var token *string         // Invisv Relay authentication token
var insecure *bool        // Ignore check of Relay server certificate?
var certDataFile *string  // File containing cert data for TLS cert pinning
var verbose *bool         // Whether to log at DEBUG level

var relayClient *masqueH2.Client

func transfer(destination io.WriteCloser, source io.ReadCloser, wg *sync.WaitGroup, logger *slog.Logger) {
	defer wg.Done()
	n, err := io.Copy(destination, source)
	if err != nil {
		if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, io.ErrClosedPipe) {
			logger.Debug("Connection closed during io.Copy", "err", err, "n", n)
		} else {
			logger.Error("Error calling io.Copy", "err", err, "n", n)
		}
	} else {
		logger.Debug("Successfully transfered", "n", n)
	}
}

// handleConnectMasque handles a CONNECT request to the proxy and returns the connected stream upon success.
func handleConnectMasque(c net.Conn, req *http.Request, logger *slog.Logger) *masqueH2.Conn {
	logger = logger.With("req", req)
	disallowedRes := &http.Response{
		StatusCode: http.StatusUnauthorized,
		ProtoMajor: 1,
		ProtoMinor: 1,
	}

	_, port, err := net.SplitHostPort(req.URL.Host)
	if err != nil {
		logger.Error("Failed to split host and port", "err", err)
		err := disallowedRes.Write(c)
		if err != nil {
			logger.Error("Error calling disallowedRes.Write", "err", err)
		}
		if err := c.Close(); err != nil {
			logger.Error("Error closing c", "err", err)
		}
		return nil
	}

	portInt, err := strconv.Atoi(port)
	if err != nil {
		logger.Error("Failed to convert port to int", "err", err)
		err := disallowedRes.Write(c)
		if err != nil {
			logger.Error("Error calling disallowedRes.Write", "err", err)
		}
		if err := c.Close(); err != nil {
			logger.Error("Error closing c", "err", err)
		}
		return nil
	}

	if masque.IsDisallowedPort(uint16(portInt)) {
		logger.Error("Disallowed port", "port", port)
		err := disallowedRes.Write(c)
		if err != nil {
			logger.Error("Error calling disallowedRes.Write", "err", err)
		}
		if err := c.Close(); err != nil {
			logger.Error("Error closing c", "err", err)
		}
		return nil
	}

	masqueConn, err := relayClient.CreateTCPStream(req.URL.Host)
	if err != nil {
		logger.Error("Failed to create TCP stream", "err", err)
		err := disallowedRes.Write(c)
		if err != nil {
			logger.Error("Error calling disallowedRes.Write", "err", err)
		}
		if err := c.Close(); err != nil {
			logger.Error("Error closing c", "err", err)
		}
		return nil
	}

	return masqueConn
}

func handleReq(c net.Conn, logger *slog.Logger) {
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		logger.Debug("Failed to read HTTP request", "err", err)
		return
	}
	logger = logger.With("conn", c, "req", req)

	// output request for debugging
	logger.Debug("handling request")

	if auth != nil && *auth != "" {
		clientAuth := req.Header.Get("Proxy-Authorization")
		if clientAuth == "" {
			response := &http.Response{
				StatusCode: http.StatusProxyAuthRequired,
				ProtoMajor: 1,
				ProtoMinor: 1,
			}
			err := response.Write(c)
			if err != nil {
				logger.Error("Error calling response.Write", "err", err)
			}
			if err := c.Close(); err != nil {
				logger.Error("Error closing c", "err", err)
			}
			return
		}

		serverAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(*auth))
		if clientAuth != serverAuth {
			response := &http.Response{
				StatusCode: http.StatusUnauthorized,
				ProtoMajor: 1,
				ProtoMinor: 1,
			}
			err := response.Write(c)
			if err != nil {
				logger.Error("Error calling response.Write", "err", err)
			}
			if err := c.Close(); err != nil {
				logger.Error("Error closing c", "err", err)
			}
			return
		}
	}

	var wg sync.WaitGroup

	if req.Method == http.MethodConnect {
		response := &http.Response{
			StatusCode: 200,
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		err := response.Write(c)
		if err != nil {
			logger.Error("Error calling response.Write", "err", err)
		}

		if masqueConn := handleConnectMasque(c, req, logger); masqueConn != nil {
			defer func() {
				if err := c.Close(); err != nil {
					logger.Error("Error closing c", "err", err)
				}
			}()
			defer func() {
				if err := masqueConn.Close(); err != nil {
					logger.Error("Error closing masqueConn", "err", err)
				}
			}()
			wg.Add(1)
			go transfer(masqueConn, c, &wg, logger.WithGroup("connect-first-transfer"))
			wg.Add(1)
			go transfer(c, masqueConn, &wg, logger.WithGroup("connect-second-transfer"))
			wg.Wait()
		}
	} else {
		// Non-CONNECT requests need to be passed through as is, without the Proxy-Authorization header.
		req.Header.Del("Proxy-Authorization")

		// If req doesn't specify a port number for the host and is http, add port 80.
		if req.URL.Scheme == "http" && !strings.Contains(req.URL.Host, ":") {
			req.URL.Host = req.URL.Host + ":80"
		}

		if masqueConn := handleConnectMasque(c, req, logger); masqueConn != nil {
			defer func() {
				if err := c.Close(); err != nil {
					logger.Error("Error closing c", "err", err)
				}
			}()
			defer func() {
				if err := masqueConn.Close(); err != nil {
					logger.Error("Error closing masqueConn", "err", err)
				}
			}()
			// Replay the request to the masque connection.
			err := req.Write(masqueConn)
			if err != nil {
				logger.Error("Error calling req.Write", "err", err)
			}
			wg.Add(1)
			go transfer(masqueConn, c, &wg, logger.WithGroup("non-connect-first-transfer"))
			wg.Add(1)
			go transfer(c, masqueConn, &wg, logger.WithGroup("non-connect-second-transfer"))
			wg.Wait()
		}
	}
}

func connectToRelay(certData []byte, logger *slog.Logger) (*masqueH2.Client, error) {
	config := masqueH2.ClientConfig{
		ProxyAddr:  fmt.Sprintf("%v:%v", *invisvRelay, *invisvRelayPort),
		AuthToken:  *token,
		Logger:     logger,
		CertData:   certData,
		IgnoreCert: *insecure,
	}

	c := masqueH2.NewClient(config)

	err := c.ConnectToProxy()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func runProxyStatusHTTPServer() {
	currentRelay := "0.0.0.0"

	ipAddr, err := net.LookupHost(*invisvRelay)
	if err == nil {
		currentRelay = ipAddr[0]
	}

	// Listen on localhost:<proxyStatusPort> and return the current proxy server IP in the format:
	// {"currentRelay":"1.2.3.4"}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(fmt.Sprintf(`{"currentRelay":"%s"}`, currentRelay)))
		if err != nil {
			log.Printf("Error writing proxy status: %v", err)
		}
	})

	log.Fatal(http.ListenAndServe(fmt.Sprintf("localhost:%d", *listenStatusPort), nil))
}

func main() {
	listenPort = flag.Int("listenPort", 32190, "Port to listen on for HTTP CONNECT requests")
	listenStatusPort = flag.Int("listenStatusPort", 32323, "Port to listen on for proxy status requests")
	auth = flag.String("auth", "", "Authentication for proxy access, in format username:password")
	invisvRelay = flag.String("invisvRelay", "", "Invisv Relay server to connect to")
	invisvRelayPort = flag.Int("invisvRelayPort", 443, "Invisv Relay server port to connect to")
	token = flag.String("token", "", "Invisv Relay authentication token")
	insecure = flag.Bool("insecure", false, "Ignore check of Relay server certificate?")
	certDataFile = flag.String("certDataFile", "", "File containing cert data for TLS cert pinning")
	verbose = flag.Bool("verbose", false, "Whether to log at DEBUG level")

	flag.Parse()
	if token == nil || *token == "" || invisvRelay == nil || *invisvRelay == "" {
		flag.Usage()
		os.Exit(1)
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	host := fmt.Sprintf("localhost:%d", *listenPort)
	l, err := net.Listen("tcp", host)
	if err != nil {
		log.Fatalf("Error in net.Listen: %v", err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			logger.Error("Error closing l", "err", err)
		}
	}()

	var certData []byte
	if *certDataFile != "" {
		certData, err = os.ReadFile(*certDataFile)
		if err != nil {
			log.Fatalf("Error reading certDataFile: %v", err)
		}
	}

	c, err := connectToRelay(certData, logger)
	if err != nil {
		log.Fatalf("Error in connect to relay: %v", err)
	}
	relayClient = c

	go runProxyStatusHTTPServer()

	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Error("Couldn't accept client connection", "err", err)
			continue
		}

		go handleReq(conn, logger.WithGroup("handleReq"))
	}
}
