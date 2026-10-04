package selfinstall

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WriteConfig writes the same config fields scripts/install-agent.ps1
// writes from its -ServerUrl/-EnrollmentToken arguments, just sourced
// from a Payload instead. For an https:// server, it also does the same
// trust-on-first-use CA bootstrap the PowerShell/bash installers do (see
// docs/TLS.md) -- plain TOFU only, since there's no way to type a pinned
// fingerprint into a double-click. An admin who wants that stronger
// guarantee uses the equivalent PowerShell command instead (offered
// alongside the downloadable installer for exactly that reason).
func WriteConfig(configPath, programDataDir string, payload Payload) error {
	if err := os.MkdirAll(programDataDir, 0o700); err != nil {
		return err
	}
	lines := []string{
		"FLEETVIEW_SERVER_URL=" + payload.ServerURL,
		"FLEETVIEW_ENROLLMENT_TOKEN=" + payload.EnrollmentToken,
		"FLEETVIEW_STATE_PATH=" + filepath.Join(programDataDir, "state.json"),
		"FLEETVIEW_SCAN_INTERVAL_SECONDS=900",
		"FLEETVIEW_METRICS_INTERVAL_SECONDS=60",
		"FLEETVIEW_JOB_POLL_SECONDS=10",
		"FLEETVIEW_REQUEST_TIMEOUT_SECONDS=60",
		"FLEETVIEW_ALLOW_INSECURE_TLS=false",
	}
	if caFile := FetchBootstrapCA(payload.ServerURL, filepath.Join(programDataDir, "ca.crt")); caFile != "" {
		lines = append(lines, "FLEETVIEW_CA_FILE="+caFile)
	}
	return os.WriteFile(configPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// FetchBootstrapCA mirrors the CA-fetch block in scripts/install-agent.ps1
// and scripts/remote-install-linux.sh: for an https:// server, fetch
// /install/ca.crt over an unverified connection (trust-on-first-use) and
// write it to destPath if it parses as a real PEM certificate. Returns ""
// (not an error -- a plain HTTP server, or one behind a real
// publicly-trusted certificate, needs none of this) for anything other
// than a successful, valid fetch, so a caller can always just check for
// an empty string rather than handle a separate error case.
func FetchBootstrapCA(serverURL, destPath string) string {
	if !strings.HasPrefix(serverURL, "https://") {
		return ""
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // #nosec G402 -- intentional one-time TOFU bootstrap, see docs/TLS.md
	}
	resp, err := client.Get(strings.TrimRight(serverURL, "/") + "/install/ca.crt")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || len(data) == 0 {
		return ""
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return ""
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return ""
	}
	if err := os.WriteFile(destPath, data, 0o644); err != nil { // #nosec G306 -- a CA certificate is public data, matches the PowerShell/bash installers' 0644
		return ""
	}
	return destPath
}
