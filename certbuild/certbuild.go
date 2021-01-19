package certbuild

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

var (
	priv interface{}
	err  error
)

// CertFiles is a struct containing filenames for cert files
type CertFiles struct {
	Cert string
	Key  string
}

// GeneratePair generates the cert and the key in the temp dir
func GeneratePair(host string) (CertFiles, error) {
	var ret CertFiles

	// Generate a good, but not extremely lenghty key to produce both the
	// certificate and the key needed to enstablish the connection.
	priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ret, err
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature

	// Defining the serial number for the certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return ret, err
	}

	// Generate template certificate with all the info needed
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Temporary but Cyphered ;)"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		IPAddresses: []net.IP{net.ParseIP(host)},
		DNSNames:    []string{host},
		IsCA:        false,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.(*ecdsa.PrivateKey).PublicKey, priv)
	if err != nil {
		return ret, err
	}

	certOut, err := ioutil.TempFile(os.TempDir(), "cert-")
	if err != nil {
		return ret, err
	}

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return ret, err
	}

	if err := certOut.Close(); err != nil {
		return ret, err
	}

	keyOut, err := ioutil.TempFile(os.TempDir(), "key-")
	if err != nil {
		return ret, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return ret, err
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return ret, err
	}

	if err := keyOut.Close(); err != nil {
		return ret, err
	}

	ret.Cert = certOut.Name()
	ret.Key = keyOut.Name()
	return ret, nil
}
