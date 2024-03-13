package testutils

import (
	"io"
	"log"
	"net"
	"path"
	"path/filepath"
	"runtime"
	"time"
)

func RootDir() string {
	_, b, _, _ := runtime.Caller(0)
	log.Printf("b: %v", b)
	d := path.Join(path.Dir(path.Dir(b)))
	return filepath.Dir(d)
}

// We want an interface that can implement net.Conn so we need to add these methods
// But we do not expect them to be called during our tests
type NetConnWrapper struct {
	io.ReadWriteCloser
}

func (r *NetConnWrapper) LocalAddr() net.Addr {
	return nil
}

func (r *NetConnWrapper) RemoteAddr() net.Addr {
	return nil
}

func (r *NetConnWrapper) SetDeadline(t time.Time) error {
	return nil
}

func (r *NetConnWrapper) SetReadDeadline(t time.Time) error {
	return nil
}

func (r *NetConnWrapper) SetWriteDeadline(t time.Time) error {
	return nil
}
