package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/5amu/hermes"

	"httpserv/certbuild"
)

var (
	port  = flag.Int("port", 8999, "Port to open")
	notls = flag.Bool("notls", false, "Switch TLS off")
	path  = flag.String("path", "./", "Path to expose")
	host  = flag.String("host", "127.0.0.1", "Set your IP")
	usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
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
	// Define basig logger
	var h hermes.Hermes

	// Define usage
	flag.Usage = usage

	// Parse arguments
	flag.Parse()

	// Get base directory
	fs := http.FileServer(http.Dir(*path))

	if *notls {
		log.Print(h.Yellow(fmt.Sprintf("Starting up the server in http mode on port %d", *port)))
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), fs))
		return
	}

	cert, err := certbuild.GeneratePair(*host)
	if err != nil {
		log.Fatal(h.Red(err.Error()))
	}

	// Launch handler for interrupt signals
	SetupCloseHandler([]string{cert.Cert, cert.Key})

	log.Print(h.Green(fmt.Sprintf("Starting up the server in https mode on port %d", *port)))
	// Launch server in https mode
	log.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%d", *port), cert.Cert, cert.Key, fs))
}
