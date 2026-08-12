package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {
	socket := flag.String("socket", "/var/run/docker.sock", "path to the Docker socket")
	addr := flag.String("addr", ":9375", "listen address")
	certFile := flag.String("tls-cert", "", "path to the TLS certificate (enables HTTPS)")
	keyFile := flag.String("tls-key", "", "path to the TLS private key")
	healthcheck := flag.Bool("healthcheck", false,
		"probe /healthz on the local listener, print nothing on success, exit non-zero on failure")
	flag.Parse()

	// The container HEALTHCHECK runs this same binary with -healthcheck. The
	// image is distroless, so there is no shell, curl or wget to write a
	// healthcheck against - the binary has to be able to probe itself.
	//
	// Checked BEFORE the GATEWAY_TOKEN requirement below: the probe does not
	// use the token, and failing the healthcheck on a missing env var would
	// report "unhealthy" for something that would have stopped the container
	// from starting at all.
	//
	// The scheme is detected rather than taken from -tls-cert, because the
	// HEALTHCHECK process does not inherit the flags the SERVER was started
	// with - see probeHealthAuto.
	if *healthcheck {
		if err := probeHealthAuto(*addr, 5*time.Second); err != nil {
			log.Printf("healthcheck failed: %v", err)
			os.Exit(1)
		}
		return
	}

	token := os.Getenv("GATEWAY_TOKEN")
	if token == "" {
		log.Fatal("GATEWAY_TOKEN is required and must not be empty")
	}

	// The Docker socket is a unix socket, so the host in this URL is a
	// placeholder that DialContext ignores.
	target, err := url.Parse("http://docker")
	if err != nil {
		log.Fatal(err)
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", *socket)
		},
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           New(Config{Token: token, Target: target, Transport: transport}),
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout on purpose: follow=1 log streams are open-ended and
		// any write deadline would sever them mid-stream.
	}

	if *certFile == "" || *keyFile == "" {
		log.Printf("docker-api-gateway listening on %s (PLAINTEXT - no -tls-cert/-tls-key), socket %s", *addr, *socket)
		log.Fatal(srv.ListenAndServe())
	}

	// Fail fast if the pair is unreadable, rather than serving and failing every
	// handshake later.
	if _, err := tls.LoadX509KeyPair(*certFile, *keyFile); err != nil {
		log.Fatalf("cannot load TLS key pair: %v", err)
	}

	// GetCertificate, NOT ListenAndServeTLS - see certReloader for why.
	srv.TLSConfig = &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: certReloader(*certFile, *keyFile),
	}
	log.Printf("docker-api-gateway listening on %s (TLS), socket %s", *addr, *socket)
	// Empty strings: the pair comes from TLSConfig.GetCertificate above.
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
