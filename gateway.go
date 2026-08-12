package main

import (
	"crypto/subtle"
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
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
// GET /containers/{id}/json (inspect) returns Config.Env. On this cluster's
// palworld container that is 157 variables including SERVER_PASSWORD and
// ADMIN_PASSWORD. Blocking inspect at the gateway means a LEAKED TOKEN still
// cannot reach those credentials, which a token check alone would not give us.
//
// GET /containers/json (the list another-app needs for its dashboard card) does
// not carry Env, which is why the two can be separated at all.
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
// Re-reading per handshake is affordable here: this gateway serves one client
// (another-app) with long-lived log streams, not high connection churn.
func certReloader(certFile, keyFile string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &c, nil
	}
}
