package http2

import (
	"context"
	"fmt"
	"io"
	"net"
)

var tcpStreamID uint64 = 0
var udpStreamID uint64 = 0

func getNextTcpStreamID() uint64 {
	r := tcpStreamID
	tcpStreamID = tcpStreamID + 1
	return r
}

func getNextUdpStreamID() uint64 {
	r := udpStreamID
	udpStreamID += 1
	return r
}

// connCleanupFunc is called when a Conn is no longer going to be used (such as
// after Close()).  It takes a bool that is true if this is a TCP connection
// and false if it is a UDP connection, and the stream ID of the connection.
type connCleanupFunc func(bool, uint64)

// Conn represents a HTTP CONNECT or CONNECT-UDP connection.
//
// Each connection has a unique stream ID, specified by the |sid| field,
// and a pair of I/O handles, namely |IoInc| and |IoOut|, designed for
// sending and receiving data via the proxied TCP/UDP connection.
//
// For CONNECT-UDP using HTTP/1.1, the |transport| field keeps track of the
// unique HTTP/1.1 TLS connection to the destination proxy server.
//
// The |Alive| field indicates the liveness of the underlying CONNECT-UDP HTTP connection.
// Users should only send data through this proxied connection if |Alive| is true.
type Conn struct {
	sid        uint64
	IoInc      io.Writer
	IoOut      io.ReadCloser
	transport  net.Conn
	alive      bool
	connCtx    context.Context
	connCancel context.CancelFunc
	isTcp      bool
	cleanup    connCleanupFunc
}

func (r *Conn) doClose() error {
	var err error
	defer r.cleanup(r.isTcp, r.sid)

	if !r.alive {
		return nil
	}

	r.alive = false
	// Close |r.IoOut| so that r.Read() returns immediately
	if r.IoOut != nil {
		err = r.IoOut.Close()
	}
	// Close decode and encode loops for CONNECT-UDP stream
	if r.connCancel != nil {
		r.connCancel()
	}
	// Close the underlying tls conn if it is CONNECT-UDP
	if r.transport != nil {
		err = r.transport.Close()
	}

	return err
}

// Sid returns the unique stream ID of the Conn.
func (r *Conn) Sid() uint64 {
	return r.sid
}

// Read reads data from the Conn's IoOut handle if the connection is alive.
// It returns an error if the connection is closed.
func (r *Conn) Read(b []byte) (int, error) {
	if r.alive {
		return r.IoOut.Read(b)
	}
	return 0, fmt.Errorf("HTTP req %d was closed", r.sid)
}

// Write writes data to the Conn's IoInc handle if the connection is alive.
// It returns an error if the connection is closed.
func (r *Conn) Write(p []byte) (int, error) {
	if r.alive {
		return r.IoInc.Write(p)
	}
	return 0, fmt.Errorf("HTTP req %d was closed", r.sid)
}

// Close closes the Conn, performing necessary cleanup.
func (r *Conn) Close() error {
	return r.doClose()
}
