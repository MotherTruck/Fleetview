// Package selfinstall reads the optional trailer the management server
// appends to the published Windows agent binary when a download is
// personalized for one enrollment (see server-rs/src/deployment.rs's
// install_agent_installer_windows and the matching
// /install/agent-windows-installer.exe route): a downloadable
// fleetview-agent.exe with its server URL and one-time enrollment token
// already baked in, so running it (as administrator) is the entire
// install -- no command line needed. The plain, unmodified binary served
// at /install/agent-windows-amd64.exe (used for the remote "Upgrade
// agent" job) carries none of this trailer and Detect simply reports
// ok=false for it, same as for any other ordinary binary.
package selfinstall

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
)

// Marker is the fixed 16-byte suffix identifying a personalized
// installer. Exported so a test (or the server, if it ever moves this
// logic) can reference the exact same constant rather than a copy that
// could drift.
const Marker = "FVAGENTINSTALL01"

// maxPayloadLen bounds the length prefix read from an untrusted file
// before trusting it enough to allocate a buffer for it -- generous for
// a small JSON object, nowhere near enough to be a memory-exhaustion
// vector from a corrupted or crafted trailer.
const maxPayloadLen = 1 << 20

// Payload is the trailer's JSON content: the two values install-agent.ps1
// would otherwise take as -ServerUrl/-EnrollmentToken command-line
// arguments.
type Payload struct {
	ServerURL       string `json:"server_url"`
	EnrollmentToken string `json:"enrollment_token"`
}

// Detect reads path's own trailing bytes looking for an appended Payload.
// It never returns an error for an ordinary binary that simply isn't a
// personalized installer -- including one that's merely too small to
// hold a trailer, has a near-miss (not exact) marker, or has a
// corrupted/truncated length prefix: all of those come back as
// ok=false, nil, exactly like a binary with no trailer at all, so a
// caller can always just check `ok` and fall through to normal behavior.
// A non-nil error is reserved for failing to even open or stat the file.
func Detect(path string) (payload Payload, ok bool, err error) {
	file, err := os.Open(path) // #nosec G304 -- path is this process's own os.Executable(), not external input
	if err != nil {
		return Payload{}, false, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return Payload{}, false, err
	}

	markerLen := int64(len(Marker))
	size := info.Size()
	if size < markerLen+4 {
		return Payload{}, false, nil
	}

	markerBuf := make([]byte, markerLen)
	if _, readErr := file.ReadAt(markerBuf, size-markerLen); readErr != nil {
		return Payload{}, false, nil
	}
	if !bytes.Equal(markerBuf, []byte(Marker)) {
		return Payload{}, false, nil
	}

	lenBuf := make([]byte, 4)
	if _, readErr := file.ReadAt(lenBuf, size-markerLen-4); readErr != nil {
		return Payload{}, false, nil
	}
	payloadLen := int64(binary.LittleEndian.Uint32(lenBuf))
	if payloadLen <= 0 || payloadLen > maxPayloadLen || payloadLen > size-markerLen-4 {
		return Payload{}, false, nil
	}

	payloadBuf := make([]byte, payloadLen)
	if _, readErr := file.ReadAt(payloadBuf, size-markerLen-4-payloadLen); readErr != nil {
		return Payload{}, false, nil
	}
	if jsonErr := json.Unmarshal(payloadBuf, &payload); jsonErr != nil {
		return Payload{}, false, nil
	}
	if payload.ServerURL == "" || payload.EnrollmentToken == "" {
		return Payload{}, false, nil
	}
	return payload, true, nil
}

// Embed appends a trailer to binary matching exactly what the server's
// install_agent_installer_windows handler produces. Not used by the
// agent itself (the server does the embedding in Rust) -- this exists
// so a test can build a round-trip fixture without duplicating the
// byte-layout logic a third time.
func Embed(exe []byte, payload Payload) ([]byte, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	lenBuf := make([]byte, 4)
	payloadLen := uint32(len(payloadBytes)) // #nosec G115 -- bounded by maxPayloadLen-sized test fixtures only
	binary.LittleEndian.PutUint32(lenBuf, payloadLen)
	out := make([]byte, 0, len(exe)+len(payloadBytes)+len(lenBuf)+len(Marker))
	out = append(out, exe...)
	out = append(out, payloadBytes...)
	out = append(out, lenBuf...)
	out = append(out, []byte(Marker)...)
	return out, nil
}
