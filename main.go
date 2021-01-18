package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	port            = flag.Int("port", 8443, "Port to open")
	path            = flag.String("path", "./", "Path to expose")
	host            = flag.String("host", "127.0.0.1", "Set your IP")
	certOut, keyOut *os.File
	priv            interface{}
	err             error
)

// SetupCloseHandler creates a 'listener' on a new goroutine which will notify the
// program if it receives an interrupt from the OS. We then handle this by calling
// our clean up procedure and exiting the program.
func SetupCloseHandler(filenames []string) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		for i := 0; i < len(filenames); i++ {
			os.Remove(filenames[i])
		}
		os.Exit(0)
	}()
}

func main() {
	// Parse arguments
	flag.Parse()

	// Get base directory
	fs := http.FileServer(http.Dir(*path))

	// Generate a good, but not extremely lenghty key to produce both the
	// certificate and the key needed to enstablish the connection.
	priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature

	// Defining the serial number for the certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	// Generate template certificate with all the info needed
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Temporary but Cyphered ;)"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		IPAddresses: []net.IP{net.ParseIP(*host)},
		DNSNames:    []string{*host},
		IsCA:        false,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.(*ecdsa.PrivateKey).PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	certOut, err := ioutil.TempFile(os.TempDir(), "cert-")
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %v", err)
	}

	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing cert.pem: %v", err)
	}

	keyOut, err := ioutil.TempFile(os.TempDir(), "key-")
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to write data to key.pem: %v", err)
	}

	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing key.pem: %v", err)
	}

	log.Printf("Starting up the server in https mode on port %d", *port)

	// Launch handler for interrupt signals
	SetupCloseHandler([]string{certOut.Name(), keyOut.Name()})

	// Launch server in https mode
	log.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%d", *port), certOut.Name(), keyOut.Name(), fs))
}
