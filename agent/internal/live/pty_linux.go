package live

import (
	"os"
	"os/exec"

	"github.com/creack/pty"
)

// linuxPTY adapts a running shell + its pty master file to the ptySession
// interface. Closing it closes the pty master, which (a) unblocks any
// goroutine currently reading from it with an error, and (b) sends the
// shell a SIGHUP via the kernel's normal controlling-terminal teardown, so
// no separate process-kill step is needed.
type linuxPTY struct {
	master *os.File
	cmd    *exec.Cmd
}

func startShell(cols, rows int) (ptySession, error) {
	shellPath := loginShell()
	cmd := exec.Command(shellPath, "-l")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	master, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if err != nil {
		return nil, err
	}
	return &linuxPTY{master: master, cmd: cmd}, nil
}

func loginShell() string {
	if shell := os.Getenv("SHELL"); shell != "" {
		if _, err := exec.LookPath(shell); err == nil {
			return shell
		}
	}
	for _, candidate := range []string{"/bin/bash", "/bin/sh"} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "/bin/sh"
}

func (p *linuxPTY) Read(buffer []byte) (int, error)  { return p.master.Read(buffer) }
func (p *linuxPTY) Write(buffer []byte) (int, error) { return p.master.Write(buffer) }

func (p *linuxPTY) Resize(cols, rows int) error {
	return pty.Setsize(p.master, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

func (p *linuxPTY) Close() error {
	err := p.master.Close()
	// Best-effort: the shell normally exits on its own once the pty master
	// closes (it receives SIGHUP as its controlling terminal goes away).
	// Explicitly killing it too covers a shell that ignores/blocks SIGHUP
	// rather than leaving an orphaned process behind.
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	return err
}
