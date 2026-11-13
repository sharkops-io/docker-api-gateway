package main

import (
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
	"time"
)

// Config is everything New needs. Target and Transport are injectable so tests
// can point at an httptest server instead of a unix socket.
type Config struct {
	Token     string
	Target    *url.URL
	Transport http.RoundTripper
}

// Exactly two paths are reachable, and the allowlist - not the token - is the
// security boundary here.
//
// GET /containers/{id}/json (inspect) returns Config.Env. On the palworld
// container that motivated this, that is 157 variables including
// SERVER_PASSWORD and ADMIN_PASSWORD. Blocking inspect at the gateway means a
// LEAKED TOKEN still cannot reach those credentials, which a token check alone
// would not give us.
//
// GET /containers/json (the list a dashboard consumer needs for a container
// status card) does not carry Env, which is why the two can be separated at
// all.
var logsPath = regexp.MustCompile(`^/containers/[A-Za-z0-9][A-Za-z0-9_.-]*/logs$`)

func allowed(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	// Reject anything not already normalised. "/containers/a/logs/../json"
	// cleans to "/containers/a/json", so comparing before against after catches
	// a traversal that would otherwise land on a blocked path.
	if path.Clean(r.URL.Path) != r.URL.Path {
		return false
	}
	return r.URL.Path == "/containers/json" || logsPath.MatchString(r.URL.Path)
}

func New(cfg Config) http.Handler {
	proxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = cfg.Target.Scheme
			r.URL.Host = cfg.Target.Host
		},
		Transport: cfg.Transport,
		// -1 flushes immediately. Docker's logs endpoint with follow=1 is an
		// open-ended stream; with default buffering the consumer sees nothing
		// until the buffer fills, which reads as "log following is broken".
		FlushInterval: -1,
	}

	mux := http.NewServeMux()

	// Unauthenticated on purpose, and deliberately NOT proxied: it must not
	// become an oracle for anything on the Docker socket. It proves the process
	// is up, nothing more.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		got := r.Header.Get("Authorization")
		// ConstantTimeCompare returns 0 for differing lengths, so a token that
		// is merely a prefix of the real one fails here too.
		if len(got) <= len(prefix) ||
			subtle.ConstantTimeCompare([]byte(got[len(prefix):]), []byte(cfg.Token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// 404 rather than 403: a blocked path should look like it does not
		// exist rather than confirming what is behind the gateway.
		if !allowed(r) {
			http.NotFound(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	return mux
}

// certReloader returns a GetCertificate func that re-reads the key pair from
// disk on EVERY handshake.
//
// This is the whole reason the server does not use ListenAndServeTLS, which
// reads the pair once at startup: after certbot renews, such a process keeps
// serving the OLD certificate until something restarts it - serving an expired
// cert for up to 90 days while every renewal reports success. Re-reading means
// a renewal takes effect on the next handshake.
//
// Re-reading per handshake is affordable here: the gateway is built for a
// handful of clients (typically one dashboard consumer) with long-lived log
// streams, not high connection churn.
func certReloader(certFile, keyFile string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &c, nil
	}
}

// probeHealth performs the container healthcheck: a GET of /healthz on the
// gateway's own listener. It lives in the binary because the image is
// distroless - there is no shell, no curl and no wget to write a HEALTHCHECK
// against.
//
// It deliberately does NOT send the token. /healthz is unauthenticated, and a
// probe that authenticated would report the container unhealthy after a token
// rotation - a configuration change, not a liveness failure.
//
// TLS verification is skipped. The server presents a certificate for its public
// FQDN while the probe dials the loopback from inside the container, so
// verifying would fail on every TLS deployment forever. This checks that the
// process is answering, not who it is.
func probeHealth(addr string, useTLS bool, timeout time.Duration) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("cannot parse address %q: %w", addr, err)
	}
	// -addr defaults to ":9375", and an empty or wildcard host is not dialable.
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}

	scheme := "http"
	client := &http.Client{Timeout: timeout}
	if useTLS {
		scheme = "https"
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, // nosemgrep
		}
	}

	resp, err := client.Get(fmt.Sprintf("%s://%s/healthz", scheme, net.JoinHostPort(host, port)))
	if err != nil {
		return fmt.Errorf("healthz unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}

// probeHealthAuto is what -healthcheck actually runs. It tries TLS first and
// then plaintext, because the container HEALTHCHECK cannot know which the
// server is using: `docker run ... -tls-cert=…` configures the ENTRYPOINT, and
// none of that reaches `CMD ["/docker-api-gateway", "-healthcheck"]`. Being
// told the scheme by a flag would mean every TLS deployment silently reported
// unhealthy while the gateway was answering perfectly well.
func probeHealthAuto(addr string, timeout time.Duration) error {
	tlsErr := probeHealth(addr, true, timeout)
	if tlsErr == nil {
		return nil
	}
	plainErr := probeHealth(addr, false, timeout)
	if plainErr == nil {
		return nil
	}
	return fmt.Errorf("healthz unreachable over TLS (%v) and plaintext (%v)", tlsErr, plainErr)
}
