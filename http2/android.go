package http2

import (
	"log/slog"
	"syscall"
)

// SocketProtector is a type representing a function that overrides Android's
// VpnService.protect().  Android's VPN hooks are necessary to capture and
// redirect all of a phone's traffic through the MASQUE tunnel, but to avoid an
// infinite loop, the traffic sent to the MASQUE proxy needs to be exempted from
// that redirection. This function enables "protection" of the given file
// descriptor (the underlying system fd for the MASQUE tunnel) from Android's VPN.
type SocketProtector func(fileDescriptor int) error

func dialerControlProtect(prot SocketProtector, logger *slog.Logger) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			if prot != nil {
				err := prot(int(fd))
				if err != nil {
					logger.Error("Error calling socket protector", "err", err)
				}
			}
		})
	}
}
