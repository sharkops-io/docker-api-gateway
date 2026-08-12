package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
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
