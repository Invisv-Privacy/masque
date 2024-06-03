package utils

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// TLSVerifyFunc takes a cert data byte slice and returns a function that can be
// passed to the tls.Config.VerifyPeerCertificate for pinning.
func TLSVerifyFunc(certData []byte) (func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("Error parsing certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Error parsing certificate: %w", err)
	}

	certVerify := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		for i := range rawCerts {
			peerCert, err := x509.ParseCertificate(rawCerts[i])
			if err == nil && cert.Equal(peerCert) {
				return nil
			}
		}
		return errors.New("no cert matches pinned cert")
	}

	return certVerify, nil
}
