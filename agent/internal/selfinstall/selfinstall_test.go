package selfinstall

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fleetview-agent-installer.exe")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

func TestDetect_RoundTrip(t *testing.T) {
	fakeExe := []byte("this is pretend PE binary content, not a real executable")
	payload := Payload{ServerURL: "https://192.168.1.50:8443", EnrollmentToken: "fv_abc123"}
	embedded, err := Embed(fakeExe, payload)
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	path := writeTemp(t, embedded)

	got, ok, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}
	if !ok {
		t.Fatalf("Detect did not find the embedded payload")
	}
	if got != payload {
		t.Fatalf("Detect returned %+v, want %+v", got, payload)
	}
}

func TestDetect_PlainBinaryNotPersonalized(t *testing.T) {
	path := writeTemp(t, []byte("a perfectly ordinary binary with no trailer at all"))
	_, ok, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect returned error for a plain binary: %v", err)
	}
	if ok {
		t.Fatalf("Detect claimed a plain binary was personalized")
	}
}

func TestDetect_TooSmallToHoldTrailer(t *testing.T) {
	path := writeTemp(t, []byte("tiny"))
	_, ok, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect returned error for a too-small file: %v", err)
	}
	if ok {
		t.Fatalf("Detect claimed a too-small file was personalized")
	}
}

func TestDetect_NearMissMarkerNotPersonalized(t *testing.T) {
	// Same length as the real marker, one byte different.
	corrupted := []byte("FVAGENTINSTALL02")
	data := append([]byte("some exe bytes"), []byte{0, 0, 0, 0}...)
	data = append(data, corrupted...)
	path := writeTemp(t, data)
	_, ok, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}
	if ok {
		t.Fatalf("Detect matched a near-miss marker")
	}
}

func TestDetect_TruncatedPayloadRejected(t *testing.T) {
	// A length prefix claiming more payload bytes than actually precede it.
	fakeExe := []byte("exe")
	lenBuf := []byte{200, 0, 0, 0} // claims 200 bytes of payload
	data := append([]byte{}, fakeExe...)
	data = append(data, lenBuf...)
	data = append(data, []byte(Marker)...)
	path := writeTemp(t, data)
	_, ok, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}
	if ok {
		t.Fatalf("Detect accepted a truncated/out-of-bounds payload length")
	}
}

func TestDetect_MalformedJSONRejected(t *testing.T) {
	fakeExe := []byte("exe")
	badJSON := []byte("{not valid json")
	lenBuf := []byte{byte(len(badJSON)), 0, 0, 0}
	data := append([]byte{}, fakeExe...)
	data = append(data, badJSON...)
	data = append(data, lenBuf...)
	data = append(data, []byte(Marker)...)
	path := writeTemp(t, data)
	_, ok, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}
	if ok {
		t.Fatalf("Detect accepted malformed JSON")
	}
}

func TestDetect_EmptyFieldsRejected(t *testing.T) {
	fakeExe := []byte("exe")
	payload := Payload{ServerURL: "", EnrollmentToken: ""}
	embedded, err := Embed(fakeExe, payload)
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	path := writeTemp(t, embedded)
	_, ok, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}
	if ok {
		t.Fatalf("Detect accepted empty ServerURL/EnrollmentToken")
	}
}

// Mirrors exactly what server-rs/src/deployment.rs's
// install_agent_installer_windows produces, byte for byte, independent
// of this package's own Embed helper -- catches any future drift between
// the Rust writer and this Go reader that round-tripping through our own
// Embed wouldn't.
func TestDetect_MatchesServerProducedLayout(t *testing.T) {
	fakeExe := []byte("pretend PE bytes")
	jsonPayload := []byte(`{"server_url":"http://10.0.0.5:8080","enrollment_token":"fv_xyz"}`)
	data := append([]byte{}, fakeExe...)
	data = append(data, jsonPayload...)
	// 4-byte little-endian length, exactly as `payload_len.to_le_bytes()`
	// produces in Rust for a u32.
	n := len(jsonPayload)
	data = append(data, byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
	data = append(data, []byte(Marker)...)
	path := writeTemp(t, data)

	got, ok, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}
	if !ok {
		t.Fatalf("Detect did not recognize the server-shaped trailer")
	}
	want := Payload{ServerURL: "http://10.0.0.5:8080", EnrollmentToken: "fv_xyz"}
	if got != want {
		t.Fatalf("Detect returned %+v, want %+v", got, want)
	}
}
