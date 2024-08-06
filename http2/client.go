package http2

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/invisv-privacy/masque"
	"github.com/invisv-privacy/masque/internal/utils"
	gohttp2 "golang.org/x/net/http2"
	"inet.af/netaddr"
)

const (
	MIN_SPARE_H2_STREAMS               = 20
	ASSUMED_MAX_CONCURRENT_STREAMS     = 100
	MAX_RETRIES                        = 3 // Retry making a connection up to MAX_RETRIES times.
	LOW_LATENCY_MAX_CONCURRENT_STREAMS = 5 // Max concurrent streams on a low latency connection.
)

// Client is a MASQUE HTTP/2 client that supports HTTP CONNECT and CONNECT-UDP.
// All CONNECT requests are multiplexed using a HTTP/2 transport.
// Each CONNECT-UDP request is performed in HTTP/1.1 and sent individually
// via its own TLS connection. Any CONNECT or CONNECT-UDP requests that
// need HTTP/3 should not directly use this.
//
// The tlsTimeout setting determines the duration the client waits when
// attempting to create a new TLS connection to the proxy. An error is returned
// if the connection is not ready to use within the specified tlsTimeout.
//
// prot if not nil should be called before connect.
type Client struct {
	proxyAddr       string
	authToken       string
	h2Transport     *gohttp2.Transport
	h2Conns         []*gohttp2.ClientConn
	tlsConn         net.Conn
	tlsTimeout      time.Duration
	tcpReqs         map[uint64]*Conn
	udpReqs         map[uint64]*Conn
	prot            SocketProtector
	certData        []byte
	makingSpare     bool
	lowLatencyAddrs map[string]bool
	mu              sync.Mutex
	logger          *slog.Logger
	ignoreCert      bool
}

// ClientConfig is a configuration for a MASQUE client to be used to set
// the configuration of a new Client to be created.
type ClientConfig struct {
	ProxyAddr       string
	AuthToken       string
	Prot            SocketProtector
	CertData        []byte
	LowLatencyAddrs []string
	Logger          *slog.Logger
	IgnoreCert      bool
}

// NewClient creates a new Client instance with the provided parameters.
func NewClient(config ClientConfig) *Client {
	l := make(map[string]bool)
	for _, s := range config.LowLatencyAddrs {
		l[s] = true
	}

	redactedConfig := config
	redactedConfig.AuthToken = "REDACTED"

	c := &Client{
		proxyAddr:       config.ProxyAddr,
		authToken:       config.AuthToken,
		h2Transport:     nil,
		h2Conns:         []*gohttp2.ClientConn{},
		tlsConn:         nil,
		tlsTimeout:      masque.MaxTLSDialTimeout,
		tcpReqs:         map[uint64]*Conn{},
		udpReqs:         map[uint64]*Conn{},
		certData:        config.CertData,
		prot:            config.Prot,
		lowLatencyAddrs: l,
		logger:          config.Logger.With("config", redactedConfig),
		ignoreCert:      config.IgnoreCert,
	}
	return c
}

// ConnectToProxy connects the Client to the proxy.
func (c *Client) ConnectToProxy() error {
	h2T, err := c.dialProxyViaH2()
	if err != nil {
		return err
	}
	c.h2Transport = h2T

	tr, err := c.dialProxyViaTLS()
	if err != nil {
		return err
	}
	c.tlsConn = tr
	return nil
}

// makeNewH2ClientConn must be called while c.mu is held.
func (c *Client) makeNewH2ClientConn(addr string) (*gohttp2.ClientConn, error) {
	ctx, _ := makeTLSDialerContext(c.tlsTimeout)
	netConn, err := c.h2Transport.DialTLSContext(ctx, "tcp", addr, nil)
	if err != nil {
		return nil, err
	}
	cc, err := c.h2Transport.NewClientConn(netConn)
	if err != nil {
		return nil, err
	}
	c.h2Conns = append(c.h2Conns, cc)

	return cc, nil
}

func (c *Client) getReadyH2ClientConnOpt(addr string, lowlatency bool) (*gohttp2.ClientConn, error) {
	var h2cc *gohttp2.ClientConn
	var spareCount uint32 = 0

	logger := c.logger.With("addr", addr)

	logger.Debug("getReadyH2ClientConnOpt")

	c.mu.Lock()
	defer c.mu.Unlock()

	for i := 0; i < len(c.h2Conns); i++ {
		cc := c.h2Conns[i]
		state := cc.State()
		if state.Closed || state.Closing {
			c.h2Conns = append(c.h2Conns[:i], c.h2Conns[i+1:]...)
			i--
			continue
		}

		var thisSpareCount uint32
		streamCount := uint32(state.StreamsActive + state.StreamsReserved + state.StreamsPending)
		if state.MaxConcurrentStreams != 0 {
			thisSpareCount = state.MaxConcurrentStreams - streamCount
		} else {
			logger.Debug("getReadyH2ClientConn assuming 100 MaxConcurrentStreams, server didn't tell us")
			thisSpareCount = ASSUMED_MAX_CONCURRENT_STREAMS - streamCount
		}
		spareCount += thisSpareCount

		if lowlatency && streamCount >= LOW_LATENCY_MAX_CONCURRENT_STREAMS {
			continue
		}

		// Explanation: Trying to make a stream on a client
		// with MaxConcurrentStreams-1 streams open is dangerous.
		// A client trying to grab the last stream may find out that
		// another thread already made that last stream. When the second-to-last client
		// calls RoundTrip() on the connection, some of the time two new streams
		// appear before the actual last client called RoundTrip().
		//
		// Simply making sure we don't attempt to use the 100th stream slot is sufficient
		// to prevent this race condition; thus, we check thisSpareCount > 1
		// instead of thisSpareCount > 0.
		if thisSpareCount > 1 && h2cc == nil && cc.ReserveNewRequest() {
			h2cc = cc
		}
	}

	spare := spareCount >= MIN_SPARE_H2_STREAMS

	// Fast path is we have a connection for now and later. That is, the following is implied:
	// if h2cc != nil && spare {
	//   log.Println("getReadyH2ClientConn fast path, spare streams", spareCount)
	// }

	// Slower path is we have a connection for now but need one for later.
	if h2cc != nil && !spare && !c.makingSpare {
		logger.Debug("getReadyH2ClientConn slower path", "spareCount", spareCount)
		c.makingSpare = true
		go func() {
			c.mu.Lock()
			defer c.mu.Unlock()

			if c.makingSpare {
				_, err := c.makeNewH2ClientConn(addr)
				if err != nil {
					logger.Error("Error calling c.makeNewH2ClientConn", "err", err, "addr", addr)
				}
				c.makingSpare = false
			}
		}()
	}

	// Slowest path is we need a new connection right now.
	if h2cc == nil {
		logger.Debug("getReadyH2ClientConn slowest path", "spareCount", spareCount)
		cc, err := c.makeNewH2ClientConn(addr)
		if err != nil {
			return nil, err
		}
		h2cc = cc
		c.makingSpare = false
	}

	return h2cc, nil
}

// CreateTCPStream creates a TCP stream to the given address using the client.
// This function should ONLY be called after successfully calling ConnectToProxy.
//
// If it succeeds, CreateTCPStream returns a Conn struct that
// provides a pair of I/O interfaces. Users can use the provided I/O interfaces
// to communicate with the target domain server in a way that is similar to a
// TCP socket's bytestream abstraction.
//
// Otherwise, CreateTCPStream returns nil and indicates the error.
func (c *Client) CreateTCPStream(addr string) (*Conn, error) {
	if c.h2Transport == nil {
		return nil, errors.New("HTTP2 connection has not been established")
	}

	// Check |addr| is a valid URL or IPPort
	var dst, authority string
	ipPort, err := netaddr.ParseIPPort(addr)
	if err != nil {
		if addr[0] >= '0' && addr[0] <= '9' {
			// Golang mis-parses FQDNs with leading digits, so treat it like an IP.
			dst = "http://" + addr
			authority = addr
		} else {
			parsedURL, err := url.Parse(addr)
			if err != nil {
				if addr[0] >= '0' && addr[0] <= '9' && strings.Contains(addr, ":") {
					// Golang mis-parses FQDNs with leading digits, so check for basic format and pass.
					dst = addr
				} else {
					return nil, errors.New("an invalid destination addr: not a IPPort or URL")
				}
			} else {
				dst = parsedURL.String()
			}
			authority = dst
		}
	} else {
		dst = fmt.Sprintf("http://%s", ipPort.String())
		authority = addr
	}

	// Craft a HTTP CONNECT request.
	pr, pw := io.Pipe()
	req, err := http.NewRequest("CONNECT", dst, pr)
	if err != nil {
		return nil, err
	}
	req.Host = authority

	if c.authToken != "" {
		req.Header.Set("Proxy-Authorization", fmt.Sprintf("PrivacyToken token=%s", c.authToken))
	} else {
		return nil, errors.New("No proxy authorization token supplied, can't connect without one.")
	}

	for i := 0; i < MAX_RETRIES; i += 1 {
		// Find a gohttp2.ClientConn that can take the request.
		_, lowlatency := c.lowLatencyAddrs[addr]
		h2Conn, err := c.getReadyH2ClientConnOpt(addr, lowlatency)
		if err != nil {
			return nil, err
		}

		// Send the request and get response.
		req.URL.Host = c.proxyAddr
		resp, err := h2Conn.RoundTrip(req)
		if err != nil {
			c.logger.Error("Error calling h2Conn.RoundTrip", "err", err, "req", req)
		} else {
			c.mu.Lock()
			// TODO: switch to use buffered writer for the input channel.
			ctx, cancel := context.WithCancel(context.Background())
			tcp := &Conn{
				sid:        getNextTcpStreamID(),
				IoInc:      pw,
				IoOut:      resp.Body,
				alive:      true,
				connCtx:    ctx,
				connCancel: cancel,
				isTcp:      true,
				cleanup:    c.connCleanup(),
			}
			c.tcpReqs[tcp.sid] = tcp
			c.mu.Unlock()

			return tcp, nil
		}
	}

	return nil, errors.New("unable to establish an h2Conn")
}

func (c *Client) makeTLSDialer() *tls.Dialer {
	var d net.Dialer
	d.Control = dialerControlProtect(c.prot, c.logger)

	t := &tls.Dialer{
		NetDialer: &d,
	}
	if c.ignoreCert {
		t.Config = &tls.Config{InsecureSkipVerify: true}
	} else if len(c.certData) > 0 {
		// This codepath is for when we're pinning to a specific proxy certificate.
		// In that case, what we care about is doing an exact match, not normal
		// hierarchical cert verification.
		certVerify, err := utils.TLSVerifyFunc(c.certData)
		if err != nil {
			c.logger.Error("Error getting certVerify func", "err", err)
			return nil
		}

		t.Config = &tls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: certVerify}
	}

	return t
}

// makeTLSDialerContext makes a context for the TLS dialer. It checks if the
// context expires before a TLS connection is complete, and returns an error if
// so. Once the TLS connection succeeds, any expiration of the context will not
// affect the connection.
func makeTLSDialerContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

// dialProxyViaH2 returns a H2 transport struct with TLS settings.
// Note: the H2 transport handles the networking operations internally.
// |prot| is called before connecting if not nil.
func (c *Client) dialProxyViaH2() (*gohttp2.Transport, error) {
	tr := &gohttp2.Transport{
		// Note that h2 Transport will bypass |network|, |addr|, and |cfg| and
		// return a default tls dialer to proxy w/ |proxyAddr|.
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			t := c.makeTLSDialer()
			return t.DialContext(ctx, "tcp", c.proxyAddr)
		},
		AllowHTTP:          true,
		DisableCompression: true,
		WriteByteTimeout:   time.Second * 3,
		ReadIdleTimeout:    time.Second * 3,
		PingTimeout:        time.Second * 2,
	}
	return tr, nil
}

// dialProxyViaTLSOnce returns a TCP connection with TLS.
// |prot| is called before connecting if not nil.
func (c *Client) dialProxyViaTLSOnce(ctx context.Context) (net.Conn, error) {
	t := c.makeTLSDialer()
	tr, err := t.DialContext(ctx, "tcp", c.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dialing proxy %s failed: %v", c.proxyAddr, err)
	}
	return tr, nil
}

func (c *Client) dialProxyViaTLS() (net.Conn, error) {
	ctx, _ := makeTLSDialerContext(c.tlsTimeout)
	for i := 0; i < masque.MaxTLSTrials; i++ {
		if tr, err := c.dialProxyViaTLSOnce(ctx); err == nil {
			return tr, nil
		} else {
			c.logger.Debug("Error calling dialProxyViaTLSOnce", "err", err)
		}
	}
	return nil, fmt.Errorf("failed to do TLS to proxy %s", c.proxyAddr)
}

// StreamDataToDatagramChunk converts UDP payload data to a CONNECT-UDP datagram chunk.
// This protocol is for tunneling a UDP stream via an HTTP proxy server.
// IETF draft: https://datatracker.ietf.org/doc/html/draft-ietf-masque-connect-udp-03
// CONNECT-UDP datagram chunk is encoded in the format of T-L-V:
// T/Type: type; L/Length: data length; V/Value: data.
// |payload| is the UDP packet payload; |l| is the payload length.
// It returns the encoded chunk in a byte slice and its total length.
func StreamDataToDatagramChunk(payload []byte, l int) ([]byte, int) {
	encode := make([]byte, 5)
	encode[0] = 0x00
	dataLength := uint(l)
	if dataLength > 63 {
		if dataLength > 16383 {
			encode[1] = 0x80 | uint8(dataLength>>24) // 4-byte length encoding
			encode[2] = uint8(dataLength >> 16)
			encode[3] = uint8(dataLength >> 8)
			encode[4] = uint8(dataLength)
			encode = append(encode[:4:4], payload...)
			return encode, l + 5
		}
		encode[1] = 0x40 | uint8(dataLength>>8) // 2-byte length encoding
		encode[2] = uint8(dataLength)
		encode = append(encode[:3:3], payload...)
		return encode, l + 3
	}
	encode[1] = uint8(dataLength) // 1-byte length encoding
	encode = append(encode[:2:2], payload...)
	return encode, l + 2
}

// datagramChunkToStreamData converts an encoded datagram chunk into a UDP raw byte slice.
// The input parameters are the CONNECT-UDP datagram chunk (chunk) and the payload length (len).
// It returns the decoded data in a byte slice and its total length.
func (c *Client) datagramChunkToStreamData(chunk []byte, chunkLength int) ([]byte, int) {
	if chunkLength < 2 || chunk[0] != 0 {
		return []byte{}, 0
	}
	v := chunk[1]
	if v&byte(0b11000000) == 0 { // 1-byte length encoding
		decode := chunk[2:]
		return decode, chunkLength - 2
	}
	if v&byte(0b11000000) == 0x40 { // 2-byte length encoding
		decode := chunk[3:]
		return decode, chunkLength - 3
	}
	if v&byte(0b11000000) == 0x80 { // 4-byte length encoding
		decode := chunk[4:]
		return decode, chunkLength - 4
	}
	if v&byte(0b11000000) == 0xc0 { // 8-byte length encoding
		decode := chunk[9:]
		return decode, chunkLength - 9
	}
	c.logger.Error("Datagram chunk encoding error", "chunk", chunk, "len", chunkLength)
	return []byte{}, 0
}

// encodeLoopUDP encodes data and sends it to the proxied UDP stream.
// |udp.transport| should be the TLS connection's reader from proxy.
// |src| should be the external data input.
func (c *Client) encodeLoopUDP(udp *Conn, src *io.PipeReader) {
	data := make([]byte, 1460)
loop:
	for {
		select {
		case <-udp.connCtx.Done():
			break loop
		default:
			{
				n, err := src.Read(data)
				if err != nil {
					if err == io.EOF {
						c.logger.Warn("EOF in udp.transport.Read")
						break loop
					}
					c.logger.Error("Error in encodeLoopUDP src.Read", "id", udp.Sid(), "err", err)
					break loop
				}

				if n > 0 {
					toSend := data[:n]
					chunk, n := StreamDataToDatagramChunk(toSend, n)
					if n > 0 {
						_, err := udp.transport.Write(chunk)
						if err != nil {
							c.logger.Error("Error in encodeLoopUDP udp.transport.Write", "id", udp.Sid(), "err", err)
							break loop
						}
					}
				}
			}
		}
	}

	if err := udp.doClose(); err != nil {
		c.logger.Error("Error from udp.doClose in encodeLoopUDP", "err", err)
	}
}

// decodeLoopUDP decodes data received from the proxied UDP stream.
// |udp.transport| should be the TLS connection's reader from proxy.
// |dst| should be the external data output.
func (c *Client) decodeLoopUDP(dst *io.PipeWriter, udp *Conn) {
	buf := make([]byte, 1500)
loop:
	for {
		select {
		case <-udp.connCtx.Done():
			c.logger.Debug("UDP stream terminated", "id", udp.Sid())
			break loop
		default:
			{
				// r.Read returns any number of bytes (and EOF) that present in its buffer.
				n, err := udp.transport.Read(buf)
				if err != nil {
					if err == io.EOF {
						c.logger.Warn("EOF in udp.transport.Read")
						break loop
					}
					c.logger.Error("Error in decodeLoopUDP udp.transport.Read", "id", udp.Sid(), "err", err)
					break loop
				}

				chunk := buf[:n:n]
				data, n := c.datagramChunkToStreamData(chunk, n)
				if n > 0 {
					_, err = dst.Write(data)
					if err != nil {
						c.logger.Error("Error in decodeLoopUDP dst.Write", "id", udp.Sid(), "err", err)
						break loop
					}
				}
			}
		}
	}

	if err := udp.doClose(); err != nil {
		c.logger.Error("Error from udp.doClose in decodeLoopUDP", "err", err)
	}
}

// CreateUDPStream creates a UDP stream to the given address using the client.
//
// This function should ONLY be called after calling |ConnectToProxy|
// successfully. If it succeeds, return a Conn struct that
// provides a pair of I/O interfaces. Users can then use the provided
// I/O interfaces to communicate with the target domain server in a way
// that is similar to an UDP datagram socket abstraction.
//
// Otherwise, it returns nil and indicates the error. It refills the connection for
// the next call.
func (c *Client) CreateUDPStream(addr string) (*Conn, error) {
	if c.tlsConn == nil {
		newTr, err := c.dialProxyViaTLS()
		if err == nil {
			c.tlsConn = newTr
		} else {
			return nil, fmt.Errorf("TLS. Failed to start a new tls conn to proxy. %v", err)
		}
	}

	ipPort, err := netaddr.ParseIPPort(addr)
	if err != nil {
		return nil, errors.New("an invalid destination addr: not a IPPort")
	}

	// Note: do not reuse a TLS connection. otherwise, the response is likely to be an error response.
	tr := c.tlsConn
	c.tlsConn = nil

	// Craft a HTTP/1.1 CONNECT-UDP request
	req := fmt.Sprintf("CONNECT-UDP masque://%s/ HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: PrivacyToken token=%s\r\n\r\n",
		ipPort.String(), ipPort.String(), c.authToken)

	// Send the request and receive the CONNECT-UDP response
	if _, err = tr.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("failed to send a CONNECT-UDP request. %v", err)
	}

	br := bufio.NewReader(tr)
	resp, err := http.ReadResponse(br, nil)

	if err != nil {
		if err := tr.Close(); err != nil {
			c.logger.Error("Error from tr.Close", "err", err)
		}
		return nil, fmt.Errorf("reading HTTP response from CONNECT-UDP to %s via proxy %s failed: %v",
			addr, c.proxyAddr, err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("proxy error from %s while dialing %s: %v",
			c.proxyAddr, addr, resp.Status)
	}

	c.mu.Lock()
	// We have to use two pairs of I/O pipe here because of encoding/decoding.
	// TODO: switch to use buffered writer for the input channel
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	udp := &Conn{
		sid:        getNextUdpStreamID(),
		IoInc:      inW,
		IoOut:      outR,
		transport:  tr,
		alive:      true,
		connCtx:    ctx,
		connCancel: cancel,
		isTcp:      false,
		cleanup:    c.connCleanup(),
	}
	c.udpReqs[udp.sid] = udp
	c.mu.Unlock()

	// read from |IoInc|, send to |udp.transport|
	go c.encodeLoopUDP(udp, inR)
	// read from |udp.transport|, send to |IoOut|
	go c.decodeLoopUDP(outW, udp)

	return udp, nil
}

func (c *Client) connCleanup() connCleanupFunc {
	return func(isTcp bool, sid uint64) {
		c.mu.Lock()
		defer c.mu.Unlock()

		if isTcp {
			delete(c.tcpReqs, sid)
		} else {
			delete(c.udpReqs, sid)
		}
	}
}
