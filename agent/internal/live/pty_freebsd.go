package live

import (
	"os"
	"os/exec"

	"github.com/creack/pty"
)

// freebsdPTY mirrors pty_linux.go's linuxPTY exactly -- creack/pty's
// openpty-based implementation works identically on FreeBSD.
type freebsdPTY struct {
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
	return &freebsdPTY{master: master, cmd: cmd}, nil
}

func loginShell() string {
	if shell := os.Getenv("SHELL"); shell != "" {
		if _, err := exec.LookPath(shell); err == nil {
			return shell
		}
	}
	// FreeBSD/OPNsense ships tcsh as root's default shell, not bash.
	for _, candidate := range []string{"/bin/tcsh", "/bin/csh", "/bin/sh"} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "/bin/sh"
}

func (p *freebsdPTY) Read(buffer []byte) (int, error)  { return p.master.Read(buffer) }
func (p *freebsdPTY) Write(buffer []byte) (int, error) { return p.master.Write(buffer) }

func (p *freebsdPTY) Resize(cols, rows int) error {
	return pty.Setsize(p.master, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

func (p *freebsdPTY) Close() error {
	err := p.master.Close()
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	return err
}
