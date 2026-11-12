package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSelfSigned writes a cert/key pair carrying the given serial, so a test
// can tell two generations apart.
func writeSelfSigned(t *testing.T, dir string, serial int64) (certPath, keyPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "docker.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "fullchain.pem")
	keyPath = filepath.Join(dir, "privkey.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// The regression this guards: with ListenAndServeTLS the key pair is read once
// at startup, so after certbot renews the process serves the OLD certificate
// until something restarts it - an expired cert served for up to 90 days while
// every renewal reports success.
func TestCertReloaderPicksUpRenewedCertWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir, 1001)

	get := certReloader(certPath, keyPath)

	first, err := get(nil)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	parsed, err := x509.ParseCertificate(first.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SerialNumber.Int64() != 1001 {
		t.Fatalf("want serial 1001, got %d", parsed.SerialNumber.Int64())
	}

	// Simulate a certbot renewal replacing the files in place.
	writeSelfSigned(t, dir, 2002)

	second, err := get(nil)
	if err != nil {
		t.Fatalf("after renewal: %v", err)
	}
	parsed2, err := x509.ParseCertificate(second.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if parsed2.SerialNumber.Int64() != 2002 {
		t.Fatalf("renewed cert not picked up: still serving serial %d", parsed2.SerialNumber.Int64())
	}
}

func TestCertReloaderReportsUnreadablePair(t *testing.T) {
	get := certReloader(filepath.Join(t.TempDir(), "missing.pem"), filepath.Join(t.TempDir(), "missing.key"))
	if _, err := get(nil); err == nil {
		t.Fatal("want an error for a missing key pair, got nil")
	}
}
