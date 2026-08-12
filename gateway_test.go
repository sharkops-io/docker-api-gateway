package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestGateway(t *testing.T) (http.Handler, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream:" + r.URL.Path))
	}))
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{Token: "s3cret", Target: u, Transport: http.DefaultTransport}), upstream
}

func do(t *testing.T, h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAllowsContainerList(t *testing.T) {
	h, up := newTestGateway(t)
	defer up.Close()
	if got := do(t, h, "GET", "/containers/json?all=true", "s3cret").Code; got != 200 {
		t.Fatalf("want 200, got %d", got)
	}
}

func TestAllowsContainerLogs(t *testing.T) {
	h, up := newTestGateway(t)
	defer up.Close()
	if got := do(t, h, "GET", "/containers/abc123/logs?follow=1&tail=100", "s3cret").Code; got != 200 {
		t.Fatalf("want 200, got %d", got)
	}
}

// The security property this service exists for: inspect returns Config.Env,
// which on palworld is 157 variables including SERVER_PASSWORD and
// ADMIN_PASSWORD. A valid token must not be enough to reach it.
func TestBlocksInspectEvenWithValidToken(t *testing.T) {
	h, up := newTestGateway(t)
	defer up.Close()
	if got := do(t, h, "GET", "/containers/abc123/json", "s3cret").Code; got != 404 {
		t.Fatalf("inspect must be unreachable, got %d", got)
	}
}

func TestBlocksWrites(t *testing.T) {
	h, up := newTestGateway(t)
	defer up.Close()
	for _, p := range []string{"/containers/abc/restart", "/containers/abc/stop", "/containers/abc/kill"} {
		if got := do(t, h, "POST", p, "s3cret").Code; got != 404 {
			t.Fatalf("%s must be blocked, got %d", p, got)
		}
	}
}

func TestBlocksOtherDockerEndpoints(t *testing.T) {
	h, up := newTestGateway(t)
	defer up.Close()
	for _, p := range []string{"/info", "/images/json", "/version", "/exec/abc/start", "/containers/abc/archive"} {
		if got := do(t, h, "GET", p, "s3cret").Code; got != 404 {
			t.Fatalf("%s must be blocked, got %d", p, got)
		}
	}
}

func TestRejectsMissingAndWrongToken(t *testing.T) {
	h, up := newTestGateway(t)
	defer up.Close()
	if got := do(t, h, "GET", "/containers/json", "").Code; got != 401 {
		t.Fatalf("missing token: want 401, got %d", got)
	}
	if got := do(t, h, "GET", "/containers/json", "wrong").Code; got != 401 {
		t.Fatalf("wrong token: want 401, got %d", got)
	}
}

// A token that is a prefix of the real one must not pass. Guards against a
// length-only or prefix comparison.
func TestRejectsPrefixToken(t *testing.T) {
	h, up := newTestGateway(t)
	defer up.Close()
	if got := do(t, h, "GET", "/containers/json", "s3cre").Code; got != 401 {
		t.Fatalf("prefix token: want 401, got %d", got)
	}
}

// A traversal that normalises onto a blocked path must not smuggle through.
func TestRejectsPathTraversal(t *testing.T) {
	h, up := newTestGateway(t)
	defer up.Close()
	if got := do(t, h, "GET", "/containers/abc/logs/../json", "s3cret").Code; got == 200 {
		t.Fatal("traversal reached upstream")
	}
}

func TestHealthzNeedsNoToken(t *testing.T) {
	h, up := newTestGateway(t)
	defer up.Close()
	if got := do(t, h, "GET", "/healthz", "").Code; got != 200 {
		t.Fatalf("want 200, got %d", got)
	}
}

// /healthz must not become an oracle for anything on the Docker socket.
func TestHealthzDoesNotProxy(t *testing.T) {
	h, up := newTestGateway(t)
	defer up.Close()
	if body := do(t, h, "GET", "/healthz", "").Body.String(); body != "ok" {
		t.Fatalf("healthz should not proxy, got %q", body)
	}
}

func TestProbeHealth(t *testing.T) {
	t.Run("reports healthy when /healthz returns ok", func(t *testing.T) {
		srv := httptest.NewServer(New(Config{Token: "s3cret", Target: &url.URL{Scheme: "http", Host: "unused"}}))
		defer srv.Close()

		if err := probeHealth(strings.TrimPrefix(srv.URL, "http://"), false, 5*time.Second); err != nil {
			t.Errorf("probeHealth: %v", err)
		}
	})

	t.Run("needs NO token", func(t *testing.T) {
		// /healthz is unauthenticated on purpose. A healthcheck that needed the
		// token would mean the container reports unhealthy on a token rotation,
		// which is a config change, not a liveness failure.
		var sawAuth bool
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sawAuth = r.Header.Get("Authorization") != ""
			New(Config{Token: "s3cret", Target: &url.URL{Scheme: "http", Host: "unused"}}).ServeHTTP(w, r)
		})
		srv := httptest.NewServer(h)
		defer srv.Close()

		if err := probeHealth(strings.TrimPrefix(srv.URL, "http://"), false, 5*time.Second); err != nil {
			t.Fatalf("probeHealth: %v", err)
		}
		if sawAuth {
			t.Error("the probe sent an Authorization header; /healthz must not need one")
		}
	})

	t.Run("fails when nothing is listening", func(t *testing.T) {
		// Port 1 is reserved and never bound, so this is a connection refusal
		// rather than a timeout.
		if err := probeHealth("127.0.0.1:1", false, 2*time.Second); err == nil {
			t.Error("expected an error when the listener is down")
		}
	})

	t.Run("fails on a non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		if err := probeHealth(strings.TrimPrefix(srv.URL, "http://"), false, 5*time.Second); err == nil {
			t.Error("expected an error for a 503")
		}
	})

	t.Run("works against TLS with a cert it cannot verify", func(t *testing.T) {
		// The server presents a cert for its public FQDN, but the probe dials
		// 127.0.0.1 from inside the container. Verification MUST be skipped or
		// every TLS deployment reports unhealthy forever. This is a liveness
		// check on the loopback, not an identity check.
		srv := httptest.NewTLSServer(New(Config{Token: "s3cret", Target: &url.URL{Scheme: "http", Host: "unused"}}))
		defer srv.Close()

		if err := probeHealth(strings.TrimPrefix(srv.URL, "https://"), true, 5*time.Second); err != nil {
			t.Errorf("probeHealth over TLS: %v", err)
		}
	})

	t.Run("normalises a bare port to loopback", func(t *testing.T) {
		// -addr defaults to ":9375"; dialing that verbatim does not work.
		srv := httptest.NewServer(New(Config{Token: "s3cret", Target: &url.URL{Scheme: "http", Host: "unused"}}))
		defer srv.Close()

		_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
		if err := probeHealth(":"+port, false, 5*time.Second); err != nil {
			t.Errorf("probeHealth with a bare port: %v", err)
		}
	})
}

// The container HEALTHCHECK cannot see the flags the container was STARTED
// with: `docker run ... -tls-cert=x` does not reach `CMD ["/gw","-healthcheck"]`.
// So the probe must work out the scheme itself, or every TLS deployment reports
// unhealthy forever while the gateway is perfectly fine.
func TestProbeHealthAuto_DetectsTheScheme(t *testing.T) {
	handler := New(Config{Token: "s3cret", Target: &url.URL{Scheme: "http", Host: "unused"}})

	t.Run("plain listener", func(t *testing.T) {
		srv := httptest.NewServer(handler)
		defer srv.Close()
		if err := probeHealthAuto(strings.TrimPrefix(srv.URL, "http://"), 5*time.Second); err != nil {
			t.Errorf("probeHealthAuto against plain HTTP: %v", err)
		}
	})

	t.Run("TLS listener", func(t *testing.T) {
		srv := httptest.NewTLSServer(handler)
		defer srv.Close()
		if err := probeHealthAuto(strings.TrimPrefix(srv.URL, "https://"), 5*time.Second); err != nil {
			t.Errorf("probeHealthAuto against TLS: %v", err)
		}
	})

	t.Run("nothing listening still fails", func(t *testing.T) {
		if err := probeHealthAuto("127.0.0.1:1", 2*time.Second); err == nil {
			t.Error("expected an error when the listener is down")
		}
	})
}
