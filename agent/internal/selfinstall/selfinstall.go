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
	AllowPlaintext  bool   `json:"allow_plaintext"`
}

// locateTrailer finds a well-formed trailer at the very end of data and
// returns the byte offset where it begins (equivalently, the length of
// the original binary before Embed appended anything) and the raw JSON
// payload bytes. ok=false for anything that isn't a complete,
// well-formed trailer -- a short file, a near-miss marker, or an
// out-of-bounds length prefix -- never an error, since "no trailer"
// must be indistinguishable from "corrupted trailer" to a caller: both
// mean "treat this as an ordinary binary." The single shared source of
// truth Detect and StripTrailer both build on, so they can never
// disagree about where the trailer starts.
func locateTrailer(data []byte) (offset int64, payloadBytes []byte, ok bool) {
	size := int64(len(data))
	markerLen := int64(len(Marker))
	if size < markerLen+4 {
		return 0, nil, false
	}
	if !bytes.Equal(data[size-markerLen:], []byte(Marker)) {
		return 0, nil, false
	}
	payloadLen := int64(binary.LittleEndian.Uint32(data[size-markerLen-4 : size-markerLen]))
	if payloadLen <= 0 || payloadLen > maxPayloadLen || payloadLen > size-markerLen-4 {
		return 0, nil, false
	}
	start := size - markerLen - 4 - payloadLen
	return start, data[start : start+payloadLen], true
}

// Detect reads path's own bytes looking for an appended Payload. It
// never returns an error for an ordinary binary that simply isn't a
// personalized installer -- including one that's merely too small to
// hold a trailer, has a near-miss (not exact) marker, or has a
// corrupted/truncated length prefix: all of those come back as
// ok=false, nil, exactly like a binary with no trailer at all, so a
// caller can always just check `ok` and fall through to normal behavior.
// A non-nil error is reserved for failing to even open or read the file.
func Detect(path string) (payload Payload, ok bool, err error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is this process's own os.Executable(), not external input
	if err != nil {
		return Payload{}, false, err
	}
	_, payloadBytes, found := locateTrailer(data)
	if !found {
		return Payload{}, false, nil
	}
	if jsonErr := json.Unmarshal(payloadBytes, &payload); jsonErr != nil {
		return Payload{}, false, nil
	}
	if payload.ServerURL == "" || payload.EnrollmentToken == "" {
		return Payload{}, false, nil
	}
	return payload, true, nil
}

// StripTrailer returns data with any trailer removed, so a binary about
// to be installed/copied elsewhere (see installService in
// service_windows.go) is an ordinary one that won't mistake itself for
// a personalized installer the next time it runs -- specifically, the
// next time it runs AS the Windows service the SCM starts, which must
// reach normal service dispatch, not Detect its own leftover trailer
// and try to self-install a second time against itself (which is
// exactly what happened before this existed: the installed copy in
// Program Files still carried the trailer, so the SCM-started service
// process immediately re-triggered self-install, hit "already
// installed", and exited without ever calling svc.Run -- the service
// existed but could never actually start). Returns data unchanged if it
// carries no trailer at all, so calling it unconditionally on every
// binary this process ever installs is always safe.
func StripTrailer(data []byte) []byte {
	offset, _, ok := locateTrailer(data)
	if !ok {
		return data
	}
	return data[:offset]
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
