package selfinstall

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestTLSServer builds a real httptest TLS server (self-signed, like
// Caddy's own generated CA) that serves its own certificate as PEM at
// /install/ca.crt, matching the real server's route.
func newTestTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewUnstartedServer(mux)
	srv.StartTLS()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	mux.HandleFunc("/install/ca.crt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(caPEM)
	})
	return srv
}

func TestFetchBootstrapCA_PlainHTTP_NoOp(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "ca.crt")
	got := FetchBootstrapCA("http://127.0.0.1:9", dest)
	if got != "" {
		t.Fatalf("expected no-op for plain HTTP, got %q", got)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("expected no file written, got err=%v", err)
	}
}

func TestFetchBootstrapCA_RealTLSServer_FetchesAndValidates(t *testing.T) {
	srv := newTestTLSServer(t)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "ca.crt")
	got := FetchBootstrapCA(srv.URL, dest)
	if got != dest {
		t.Fatalf("FetchBootstrapCA returned %q, want %q", got, dest)
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("reading fetched CA: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("fetched file is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("fetched PEM does not parse as a certificate: %v", err)
	}
	if !cert.Equal(srv.Certificate()) {
		t.Fatalf("fetched certificate does not match the server's real certificate")
	}
}

func TestFetchBootstrapCA_FetchedCAActuallyVerifiesTheServer(t *testing.T) {
	// The real point of this bootstrap: once fetched, the CA should let a
	// properly-verified (non-InsecureSkipVerify) client trust this exact
	// server -- proving this isn't just downloading bytes, but a real,
	// usable trust anchor, matching what the agent's own client.go does
	// with FLEETVIEW_CA_FILE afterward.
	srv := newTestTLSServer(t)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "ca.crt")
	if FetchBootstrapCA(srv.URL, dest) == "" {
		t.Fatalf("FetchBootstrapCA failed")
	}

	caPEM, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("reading fetched CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("fetched CA could not be loaded into a cert pool")
	}
	verifiedClient := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
	resp, err := verifiedClient.Get(srv.URL + "/install/ca.crt")
	if err != nil {
		t.Fatalf("a properly TLS-verified request against the fetched CA failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
}

func TestFetchBootstrapCA_UnreachableServer_NoOp(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "ca.crt")
	got := FetchBootstrapCA("https://127.0.0.1:1", dest)
	if got != "" {
		t.Fatalf("expected no-op for an unreachable server, got %q", got)
	}
}

func TestFetchBootstrapCA_NonCertificateResponse_NoOp(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/install/ca.crt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("this is not a certificate at all"))
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.StartTLS()
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "ca.crt")
	got := FetchBootstrapCA(srv.URL, dest)
	if got != "" {
		t.Fatalf("expected no-op for a non-certificate response, got %q", got)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("expected no file written for invalid content")
	}
}

func TestFetchBootstrapCA_404_NoOp(t *testing.T) {
	mux := http.NewServeMux()
	// no handler registered -> 404
	srv := httptest.NewUnstartedServer(mux)
	srv.StartTLS()
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "ca.crt")
	got := FetchBootstrapCA(srv.URL, dest)
	if got != "" {
		t.Fatalf("expected no-op for a 404 (e.g. a real public CA with no Caddy ca.crt route), got %q", got)
	}
}

func TestWriteConfig_PlainHTTP_NoCALine(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.env")
	payload := Payload{ServerURL: "http://192.168.1.50:8080", EnrollmentToken: "fv_tok123"}
	if err := WriteConfig(configPath, dir, payload); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}
	content := string(data)
	for _, want := range []string{
		"FLEETVIEW_SERVER_URL=http://192.168.1.50:8080",
		"FLEETVIEW_ENROLLMENT_TOKEN=fv_tok123",
		"FLEETVIEW_ALLOW_INSECURE_TLS=false",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("config missing expected line %q; got:\n%s", want, content)
		}
	}
	if strings.Contains(content, "FLEETVIEW_CA_FILE") {
		t.Errorf("plain HTTP config should not reference a CA file; got:\n%s", content)
	}
}

func TestWriteConfig_AllowPlaintext_WritesOptIn(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.env")
	payload := Payload{ServerURL: "http://192.168.1.50:8080", EnrollmentToken: "fv_tok123", AllowPlaintext: true}
	if err := WriteConfig(configPath, dir, payload); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}
	if !strings.Contains(string(data), "FLEETVIEW_ALLOW_PLAINTEXT=true") {
		t.Errorf("expected FLEETVIEW_ALLOW_PLAINTEXT=true; got:\n%s", string(data))
	}
}

func TestWriteConfig_HTTPS_IncludesCALine(t *testing.T) {
	srv := newTestTLSServer(t)
	defer srv.Close()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.env")
	payload := Payload{ServerURL: srv.URL, EnrollmentToken: "fv_tok456"}
	if err := WriteConfig(configPath, dir, payload); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}
	content := string(data)
	wantCALine := "FLEETVIEW_CA_FILE=" + filepath.Join(dir, "ca.crt")
	if !strings.Contains(content, wantCALine) {
		t.Errorf("https config missing expected CA line %q; got:\n%s", wantCALine, content)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.crt")); err != nil {
		t.Errorf("expected ca.crt to actually be written: %v", err)
	}
}
