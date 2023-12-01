// Issue 89
// Should avoid Passing hard coded credential into X509.ParseCertificates

package main

import (
	"crypto/x509"
	"fmt"
	"log"
)

func main() {
	// Load the hard-coded certificate
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIC+zCCAeOgAwIBAgIULG+L6g2nrlU+jJ6UxMR6UkmUV6owDQYJKoZIhvcNAQEL
BQAwDTELMAkGA1UEAxMCVGVzdDAeFw0yMDEyMjgxNjE3MTdaFw0zMDA4MjgxNjE3
MTdaMA0xCzAJBgNVBAMTAkVFMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzKpS
kmllGn8mHlL4m4sEjKDFC2e3qz/9D2UP7osOXcmZiKTyNpOOtSpL29NcN/xfljKg
FFVsjW9BvZ7VJfhwOqM7MDUGA1UdEQQqMCiCEG15LmV4YW1wbGUuY29tMAoGCCqG
SM49BAMCA0gAMEUCIQC6A0UfW8zvR9Ih5eVWTnfYiwyWq3v2N5N5cSKtg8WRAQIg
fM0bBQoO3f0q0yLzBtswltRt+99x+xWp7E/hMGltgMI=
-----END CERTIFICATE-----`)

	// Parse the certificate
	cert, err := x509.ParseCertificates(certPEM)
	if err != nil {
		log.Fatal("Error parsing certificate:", err)
	}
	fmt.Print(cert)
}
