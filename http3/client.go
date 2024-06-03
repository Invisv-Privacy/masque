package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/invisv-privacy/masque/internal/utils"
	"github.com/quic-go/quic-go"
	quich3 "github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// datagramRcvQueueLen is the length of the receive queue for DATAGRAM frames (RFC 9221)
const datagramRcvQueueLen = 128

const defaultMaxIncomingStreams = 100

const defaultMaxIdleTimeout = time.Minute * 10

const defaultConnectTimeout = time.Second * 10

// Client is an object that should not be initialized manually.
// Please call NewClient() to get a correctly initialized client.
type Client struct {
	proxyAddr string

	// Token used for Proxy-Authorization headers.
	authToken string

	// Pinned certificate bytes
	certData []byte

	// RoundTripper object that executes flow initialization with the proxy.
	roundTripper *quich3.RoundTripper

	// HTTP Client object that uses the RoundTripper.
	httpClient *http.Client

	// Synchronized map of H3_DATAGRAM flow ID to DatagramStream object.
	datagramStreams *sync.Map

	// Checks if any request has been sent to the proxy yet; needed to ensure
	// QUIC connection options have been parsed by the proxy.
	hasBeenUsed bool

	// Context and cancel functions used to control the datagram receiver loop.
	datagramCtx    context.Context
	datagramCancel context.CancelFunc

	// Pool and ID variables used to track available flow identifiers for H3_DATAGRAM flows.
	datagramIDPool map[uint64]bool
	maxDatagramID  uint64

	// Checks if the datagram receive loop has started.
	receiveLoopStarted bool

	// Error channel from the datagram receive loop.
	receiveLoopError chan error

	mutex sync.Mutex

	logger *slog.Logger
}

// ClientConfig is options to give when creating a new Client with NewClient().
// Note that sane defaults are used when value is not provided/initialized.
type ClientConfig struct {
	// The proxy to connect to in host:port format.
	ProxyAddr string

	// Maximium number of incoming streams. Typically not an issue, as
	// the Client will not need to handle incoming connections.
	MaxIncomingStreams int64

	// Maximum time to keep a proxy stream idle. Defaults to 10 minutes.
	MaxIdleTimeout time.Duration

	// Timeout for the HTTP client to initally connect to the server.
	// If a response is not received by the time this occurs, the connection will break.
	// Defaults to 10 seconds.
	ConnectTimeout time.Duration

	// Authorization token string to pass in a Proxy-Authorization header when
	// connecting to a proxy server. Note that the token is formatted into the header
	// automatically; it is not necessary to provide the full value-string that
	// would appear in an HTTP header.
	AuthToken string

	// Pinned cert bytes
	CertData []byte

	// Set to true to ignore invalid/unverifiable certs provided by the proxy server.
	// Note that if UseCertSideLoader is true, this value is irrelevant after a
	// cert file has been loaded with LoadNewCert().
	Insecure bool

	Logger *slog.Logger
}

// DatagramStream is an object for Proxied UDP Streams that implements I/O functionality.
// This object contains information necessary to communicate with the Client
// message receiver loop.
//
// Read/Write on a DatagramStream works as expected, though note it will use
// Datagram framing semantics (each block is an individual UDP packet).
//
// It is important that the caller DO NOT close the quic.Stream OR the quic.Connection
// object that is given inside of the struct.
type DatagramStream struct {
	// stream is the underlying quic.Stream
	stream quic.Stream

	// conn is the underlying quic.Connection
	conn quic.Connection

	// ctx is a DatagramStream specific context
	ctx context.Context

	// ctx is a DatagramStream specific cancel function
	cancel context.CancelFunc

	// id is an id unique to this DatagramStream
	id uint64

	// varIntID is the quicvarint representation of this DatagramStream's id
	varIntID []byte

	// recvQueue is a channel through which the receive loop can pass Datagrams specific to this
	// DatagramStream for Reading
	recvQueue chan []byte

	// closeTrigger is a function called on DatagramStream.Close
	closeTrigger func() error

	// isClosed is an atomic bool that represent whether the DatagramStream is closed
	isClosed *atomic.Bool
}

// ErrDatagramStreamClosed is an error representing a failure where the DatagramStream is closed
var ErrDatagramStreamClosed = fmt.Errorf("stream has been closed")

// sanitizeOptionsWithDefaults sets the default values for ProxyOptions.
func sanitizeOptionsWithDefaults(opt ClientConfig) (ClientConfig, error) {
	if opt.MaxIncomingStreams == 0 {
		opt.MaxIncomingStreams = defaultMaxIncomingStreams
	}
	if opt.MaxIdleTimeout == 0 {
		opt.MaxIdleTimeout = defaultMaxIdleTimeout
	}
	if opt.ConnectTimeout == 0 {
		opt.ConnectTimeout = defaultConnectTimeout
	}

	return opt, nil
}

// NewClient provides a method that returns a new Client object, creating
// a new http3.RoundTripper object dedicated to be used with the provided proxy address.
//
// Note that proxyAddr is in ip:port format, where 'ip' may be a DNS address if desired.
// TODO: Find a way to disable congestion control on the QUIC connection (but not streams)
func NewClient(config ClientConfig) (*Client, error) {
	opt, err := sanitizeOptionsWithDefaults(config)
	if err != nil {
		return nil, err
	}

	redactedConfig := config
	redactedConfig.AuthToken = "REDACTED"

	proxyURI, err := url.Parse(fmt.Sprintf("https://%s", opt.ProxyAddr))
	if err != nil {
		return nil, fmt.Errorf("Error parsingURI: %w", err)
	}

	config.Logger.Debug("parsed requestURI", "proxyURI", proxyURI)
	newClient := &Client{
		proxyAddr:          opt.ProxyAddr,
		authToken:          opt.AuthToken,
		certData:           config.CertData,
		datagramIDPool:     make(map[uint64]bool),
		maxDatagramID:      0,
		datagramStreams:    &sync.Map{},
		receiveLoopStarted: false,
		logger:             config.Logger.With("config", redactedConfig),
		receiveLoopError:   make(chan error, 1),
	}

	qconf := quic.Config{
		EnableDatagrams:    true,
		MaxIncomingStreams: opt.MaxIncomingStreams,
		MaxIdleTimeout:     opt.MaxIdleTimeout,
	}

	tlsClientConfig := &tls.Config{}

	if opt.Insecure {
		tlsClientConfig.InsecureSkipVerify = true
	} else if opt.CertData != nil {
		certVerify, err := utils.TLSVerifyFunc(opt.CertData)
		if err != nil {
			return nil, fmt.Errorf("Error creating TLS cert verify function: %w", err)
		}

		tlsClientConfig.VerifyPeerCertificate = certVerify
	}

	roundTripper := &quich3.RoundTripper{
		TLSClientConfig: tlsClientConfig,
		QuicConfig:      &qconf,
		Proxy:           http.ProxyURL(proxyURI),
		EnableDatagrams: true,
	}

	newClient.roundTripper = roundTripper

	httpClient := &http.Client{
		Transport: roundTripper,
	}
	newClient.httpClient = httpClient

	return newClient, nil
}

// datagramReceiveLoop pulls datagrams from the quic.Connection object
// and places them inside of the correct DatagramStream.
// It performs parsing of the initial VarInt that preceeds each datagram,
// and places the byte slice inside of a channel to later be read.
// Should only be started once; check receiveLoopStarted before running this.
func (c *Client) datagramReceiveLoop(conn quic.Connection) {
	for {
		select {
		case <-c.datagramCtx.Done():
			c.receiveLoopError <- nil
			return
		default:
			// TODO: check this is correct context
			datagram, err := conn.ReceiveDatagram(c.datagramCtx)
			if err != nil {
				c.logger.Error("Error in conn.ReceiveDatagram", "err", err)
				c.receiveLoopError <- err
				continue
			}
			c.logger.Debug("Received Datagram", "datagram", datagram)

			reader := bytes.NewReader(datagram)
			r := quicvarint.NewReader(reader)
			datagramID, err := quicvarint.Read(r)
			if err != nil {
				c.logger.Error("Error in quicvarint.Read", "err", err)
				c.receiveLoopError <- err
				continue
			}
			message := datagram[(len(datagram) - reader.Len()):]
			t, ok := c.datagramStreams.Load(datagramID)
			if !ok || t == nil {
				// TODO: Log mystery packet counter (datagram flow may have been closed already)
				c.logger.Error("Not found in datagramStreams", "datagramID", datagramID)
				continue
			}
			targetStream, ok := t.(*DatagramStream)
			if !ok {
				c.logger.Error("MAJOR BUG: datagramStreams was holding non *DatagramStream object")
			}

			select {
			// Our receive queue has room for this message
			case targetStream.recvQueue <- message:
			default:
				// Our receive queue is full and does not have room for this message
				c.logger.Warn("receive queue full, dropping message", "message", message, "datagramID", datagramID)
				continue
			}
		}
	}
}

// startReceiveLoop starts datagramReceiveLoop with a given quic.Connection, first checking
// if it already has been started.
func (c *Client) startReceiveLoop(conn quic.Connection) error {
	c.logger.Info("startReceiveLoop", "conn", conn)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.receiveLoopStarted {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.datagramCtx = ctx
	c.datagramCancel = cancel

	go c.datagramReceiveLoop(conn)

	c.receiveLoopStarted = true
	return nil
}

func (c *Client) cancelAllUDPStreams() error {
	streamList := []*DatagramStream{}
	c.datagramStreams.Range(func(id, stream interface{}) bool {
		streamC, ok := stream.(*DatagramStream)
		if ok {
			streamList = append(streamList, streamC)
		} else {
			c.logger.Error("datagramStreams contained non DatagramStream value", "id", id, "stream", stream)
		}
		return true
	})
	var err error
	for _, stream := range streamList {
		tErr := stream.Close()
		if tErr != nil {
			err = tErr
		}
	}
	return err
}

func (c *Client) stopReceiveLoop() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.receiveLoopStarted {
		c.datagramCancel()
		err := <-c.receiveLoopError
		c.receiveLoopStarted = false

		if err != nil {
			return err
		}
	}
	return nil
}

// getNewDatagramID gets a new H3_DATAGRAM Flow ID to be used with a UDP
// stream.
func (c *Client) getNewDatagramID() uint64 {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	ret := c.maxDatagramID
	for k := range c.datagramIDPool {
		ret = k
		break
	}
	if ret == c.maxDatagramID {
		// H3_DATAGRAM IDs must be even.
		c.maxDatagramID = c.maxDatagramID + 2
	} else {
		delete(c.datagramIDPool, ret)
	}

	return ret
}

// releaseDatagramID releases a datagram flow ID back into the pool for use.
func (c *Client) releaseDatagramID(id uint64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.datagramIDPool[id] = true
}

func isIdleTimeoutError(err error) bool {
	e, ok := err.(*url.Error)
	if ok {
		_, ok := e.Err.(*quic.IdleTimeoutError)
		if ok {
			return true
		}
	}
	return false
}

func (c *Client) refreshRoundTripper() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	err := c.roundTripper.Close()
	c.hasBeenUsed = false
	return err
}

// CreateTCPStream creates a TCP Stream through the proxy to the designated destination.
// Note that destAddr is in ip:port format, where ip CANNOT be a DNS address.
// This TCP stream is the responsibility of the caller to Close() properly.
func (c *Client) CreateTCPStream(destAddr string) (quich3.Stream, error) {
	fullAddr := fmt.Sprintf("https://%s/", destAddr)

	req, err := http.NewRequest(http.MethodConnect, fullAddr, nil)
	if err != nil {
		return nil, err
	}

	if c.authToken != "" {
		req.Header.Add("Proxy-Authorization", fmt.Sprintf("PrivacyToken token=%s", c.authToken))
	}

	rsp, err := c.httpClient.Do(req)
	if err != nil {
		if isIdleTimeoutError(err) {
			err = c.refreshRoundTripper()
			if err != nil {
				return nil, err
			}
			rsp, err = c.httpClient.Do(req)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	} else if rsp.StatusCode < 200 || rsp.StatusCode >= 300 {
		return nil, fmt.Errorf("CONNECT failed: error code %d", rsp.StatusCode)
	}

	c.logger.Debug("Got response", "destAddr", destAddr, "rsp", rsp)

	hstr, e := rsp.Body.(quich3.HTTPStreamer)
	if !e {
		return nil, fmt.Errorf("failed to convert HTTPStreamer object")
	}
	str := hstr.HTTPStream()

	c.hasBeenUsed = true

	return str, nil
}

// CreateUDPStream creates a UDP Stream through the proxy
// Also starts the receiver loop for datagrams if it hasn't already been started.
// Returns a DatagramStream object that becomes the responsibility of the caller to Close().
// destAddr should be in ip:port format, where ip CANNOT be a DNS address.
func (c *Client) CreateUDPStream(destAddr string) (*DatagramStream, error) {
	fullAddr := fmt.Sprintf("masque://%s/", destAddr)

	req, err := http.NewRequest("CONNECT-UDP", fullAddr, nil)
	if err != nil {
		return nil, err
	}

	if c.authToken != "" {
		req.Header.Add("Proxy-Authorization", fmt.Sprintf("PrivacyToken token=%s", c.authToken))
	}

	var thisDatagramID uint64
	for {
		thisDatagramID = c.getNewDatagramID()
		_, idInUse := c.datagramStreams.Load(thisDatagramID)
		if !idInUse {
			break
		}
		c.logger.Error("ID Reuse detected in Client", "thisDatagramID", thisDatagramID)
	}

	req.Header.Add("Datagram-Flow-Id", fmt.Sprintf("%d", thisDatagramID))

	var rsp *http.Response
	c.logger.Debug("Attempting to make request", "req", req)
	rsp, err = c.httpClient.Do(req)
	if err != nil {
		if isIdleTimeoutError(err) {
			if err := c.stopReceiveLoop(); err != nil {
				return nil, fmt.Errorf("failed to stopReceiveLoop: %w", err)
			}
			err = c.refreshRoundTripper()
			if err != nil {
				c.releaseDatagramID(thisDatagramID)
				return nil, fmt.Errorf("failed to refreshRoundTripper: %w: ", err)
			}

			rsp, err = c.httpClient.Do(req)
			if err != nil {
				c.releaseDatagramID(thisDatagramID)
				return nil, fmt.Errorf("failed to httpClient.Do(req): %w: ", err)
			}
		} else {
			c.releaseDatagramID(thisDatagramID)
			return nil, err
		}
	}

	c.logger.Debug("Got response", "destAddr", destAddr, "rsp", rsp)

	// Per the quic-go documentation:
	// The HTTPStreamer allows taking over a HTTP/3 stream. This is implemented by http.Response.Body
	hstr, ok := rsp.Body.(quich3.HTTPStreamer)
	if !ok {
		c.releaseDatagramID(thisDatagramID)
		return nil, fmt.Errorf("failed to convert HTTPStreamer object")
	}
	// HTTPStream allows us to hijack the http.Response.Body
	str := hstr.HTTPStream()
	// conn is the associated quic.Connection
	conn := hstr.HTTPConnection()
	if conn == nil {
		c.releaseDatagramID(thisDatagramID)
		return nil, fmt.Errorf("failed to get HTTP Connection object")
	}

	b := []byte{}
	b = quicvarint.Append(b, thisDatagramID)

	ctx, cancel := context.WithCancel(context.Background())

	atomicBool := atomic.Bool{}
	atomicBool.Store(false)

	ret := &DatagramStream{
		stream:    str,
		conn:      conn,
		ctx:       ctx,
		cancel:    cancel,
		id:        thisDatagramID,
		varIntID:  b,
		recvQueue: make(chan []byte, datagramRcvQueueLen),
		closeTrigger: func() error {
			c.datagramStreams.Delete(thisDatagramID)
			c.releaseDatagramID(thisDatagramID)
			return nil
		},
		isClosed: &atomicBool,
	}

	c.datagramStreams.Store(thisDatagramID, ret)

	if !c.receiveLoopStarted {
		if err := c.startReceiveLoop(conn); err != nil {
			return nil, fmt.Errorf("failed to startReceiveLoop: %w", err)
		}
	}

	return ret, nil
}

// Close closes a Client object. This will kill the datagram receiver loop, and
// any active stream objects.
func (c *Client) Close() error {
	if err := c.roundTripper.Close(); err != nil {
		return err
	}
	if err := c.stopReceiveLoop(); err != nil {
		return fmt.Errorf("failed to stopReceiveLoop: %w", err)
	}
	// We shouldn't need to cancel TCP Streams, since they're
	// using an underlying HTTP stream object
	if err := c.cancelAllUDPStreams(); err != nil {
		return err
	}

	return nil
}

// Read reads from a datagram stream. Blocks if no data is available.
// If the provided []byte slice is not large enough for the message,
// it will be truncated and the remainder dropped.
func (s *DatagramStream) Read(b []byte) (int, error) {
	select {
	case message, ok := <-s.recvQueue:
		if ok {
			log.Printf("message received: %v\n", message)
			copied := copy(b, message)
			return copied, nil
		} else {
			return 0, fmt.Errorf("stream channel closed")
		}
	case <-s.ctx.Done():
		return 0, ErrDatagramStreamClosed
	}

}

// Write writes to a datagram stream. May block if the stream buffer is full.
// Note that this function requires prepending 1 to 9 bytes to send the datagram:
// this means that the MTU size of the connection will be below what the caller
// may expect.
func (s *DatagramStream) Write(b []byte) (int, error) {
	select {
	case <-s.ctx.Done():
		return 0, ErrDatagramStreamClosed
	default:
		wireMsg := append(s.varIntID, b...)
		err := s.conn.SendDatagram(wireMsg)
		return len(b), err
	}
}

// Close closes a DatagramStream, returning its flow ID to the pool by calling
// its closeTrigger().
func (s *DatagramStream) Close() error {
	if !s.isClosed.Swap(true) {
		return nil
	}

	err := s.closeTrigger()
	if err != nil {
		return err
	}

	// DO NOT close the conn (Connection) object!
	// It holds all streams (TCP and UDP) to the proxy,
	// far outside the scope of this single stream.
	s.cancel()
	err = s.stream.Close()
	if err != nil {
		return err
	}

	return nil
}
