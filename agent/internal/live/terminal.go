package live

import (
	"encoding/base64"
	"io"
	"log"
	"sync"
)

// terminalHandler manages at most one active terminal session at a time,
// matching the server's single-viewer-per-device enforcement (see
// server/app/live.py's claim_terminal). Every control message is scoped by
// the server-issued session id, so a stale message from a session that
// already ended (crossed in flight with a new one starting) is ignored
// rather than acted on.
//
// terminal_input/terminal_output data is base64-encoded: raw PTY output can
// contain arbitrary bytes (partial multi-byte sequences, control codes)
// that aren't valid UTF-8 on their own, and the wire format here is JSON
// text. The server never interprets this field -- it just relays it -- so
// this is purely an agent<->dashboard convention (the dashboard's terminal
// UI decodes/encodes the same way).
type terminalHandler struct {
	send   func(payload any)
	logger *log.Logger

	mu      sync.Mutex
	session string
	pty     ptySession
}

type terminalOutputMessage struct {
	Type    string `json:"type"`
	Session string `json:"session"`
	Data    string `json:"data"`
}

type terminalClosedMessage struct {
	Type    string `json:"type"`
	Session string `json:"session"`
	Reason  string `json:"reason"`
}

func (t *terminalHandler) start(session string, cols, rows int) {
	t.mu.Lock()
	if t.pty != nil {
		t.closeLocked()
	}
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	pty, err := startShell(cols, rows)
	if err != nil {
		t.mu.Unlock()
		t.send(terminalClosedMessage{Type: "terminal_closed", Session: session, Reason: "failed to start shell: " + err.Error()})
		return
	}
	t.session = session
	t.pty = pty
	t.mu.Unlock()
	go t.copyOutput(session, pty)
}

func (t *terminalHandler) copyOutput(session string, pty ptySession) {
	buffer := make([]byte, 32*1024)
	for {
		n, err := pty.Read(buffer)
		if n > 0 {
			t.send(terminalOutputMessage{Type: "terminal_output", Session: session, Data: base64.StdEncoding.EncodeToString(buffer[:n])})
		}
		if err != nil {
			reason := "exited"
			if err != io.EOF {
				reason = err.Error()
			}
			t.send(terminalClosedMessage{Type: "terminal_closed", Session: session, Reason: reason})
			t.mu.Lock()
			if t.session == session {
				t.session = ""
				t.pty = nil
			}
			t.mu.Unlock()
			return
		}
	}
}

func (t *terminalHandler) write(session, data string) {
	t.mu.Lock()
	pty, current := t.pty, t.session
	t.mu.Unlock()
	if pty == nil || current != session {
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return
	}
	_, _ = pty.Write(decoded)
}

func (t *terminalHandler) resize(session string, cols, rows int) {
	t.mu.Lock()
	pty, current := t.pty, t.session
	t.mu.Unlock()
	if pty == nil || current != session || cols <= 0 || rows <= 0 {
		return
	}
	_ = pty.Resize(cols, rows)
}

func (t *terminalHandler) stopSession(session string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.session == session {
		t.closeLocked()
	}
}

func (t *terminalHandler) stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closeLocked()
}

// closeLocked must be called with t.mu held. It only closes the PTY;
// copyOutput (if running) observes the resulting read error, sends
// terminal_closed itself, and clears t.session/t.pty under the lock -- so a
// concurrent stop() and natural shell exit can never send two competing
// closed notifications for the same session, only whichever gets there
// first.
func (t *terminalHandler) closeLocked() {
	if t.pty != nil {
		_ = t.pty.Close()
	}
}
