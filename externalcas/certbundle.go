package externalcas

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// splitCertificateBundle splits a PEM-encoded certificate bundle into a leaf certificate
// and a chain of intermediate certificates. The first certificate in the bundle is treated
// as the leaf certificate, and all subsequent certificates are treated as intermediates.
func splitCertificateBundle(pemBytes []byte) (*x509.Certificate, []*x509.Certificate, error) {
	var certificates []*x509.Certificate
	remaining := pemBytes
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certificates = append(certificates, cert)
		}
		remaining = rest
	}

	if len(certificates) == 0 {
		return nil, nil, errors.New("no certificates found in bundle")
	}

	leafCert := certificates[0]
	var intermediates []*x509.Certificate
	if len(certificates) > 1 {
		intermediates = certificates[1:]
	}

	return leafCert, intermediates, nil
}
