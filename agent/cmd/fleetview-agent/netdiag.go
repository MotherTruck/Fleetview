package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"time"
)

// validDiagnosticTarget mirrors the server's own validation (see
// NetworkDiagnosticInput in server/app/deployment.py) as defense in depth:
// even though exec.Command never invokes a shell (so classic shell
// injection isn't the concern), a target starting with "-" could still be
// parsed as a flag by ping/traceroute's own argument parser rather than as
// a hostname.
var validDiagnosticTarget = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$`)

// runNetworkDiagnostic runs one bounded, read-only network diagnostic and
// returns its output, an exit code (0 on success, matching the other job
// types' convention), and an error. Unlike RUN_COMMAND (arbitrary shell
// access, admin-only), these four tools are fixed and their arguments are
// structured, not free text -- ping/traceroute run as direct argv exec
// (never through a shell), and dns/port_check don't spawn a process at
// all, just calling into Go's own net package.
func runNetworkDiagnostic(parent context.Context, tool, target string, port int) (string, int, error) {
	if !validDiagnosticTarget.MatchString(target) {
		return "", -1, fmt.Errorf("invalid target %q", target)
	}
	switch tool {
	case "ping":
		name, args := pingCommand(target)
		return runDiagnosticProcess(parent, name, args)
	case "traceroute":
		name, args := tracerouteCommand(target)
		return runDiagnosticProcess(parent, name, args)
	case "dns":
		return runDNSLookup(target)
	case "port_check":
		if port < 1 || port > 65535 {
			return "", -1, fmt.Errorf("invalid port %d", port)
		}
		return runPortCheck(target, port)
	default:
		return "", -1, fmt.Errorf("unsupported network diagnostic tool %q", tool)
	}
}

func pingCommand(target string) (string, []string) {
	if runtime.GOOS == "windows" {
		return "ping", []string{"-n", "4", target}
	}
	return "ping", []string{"-c", "4", "-W", "2", target}
}

func tracerouteCommand(target string) (string, []string) {
	if runtime.GOOS == "windows" {
		return "tracert", []string{"-h", "15", target}
	}
	return "traceroute", []string{"-m", "15", "-w", "2", target}
}

func runDiagnosticProcess(parent context.Context, name string, args []string) (string, int, error) {
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	output, runErr := cmd.CombinedOutput()
	code := -1
	if runErr == nil {
		code = 0
	} else if exit, ok := runErr.(*exec.ExitError); ok {
		code = exit.ExitCode()
	}
	if ctx.Err() != nil {
		runErr = ctx.Err()
	}
	if len(output) > 262_144 {
		output = output[len(output)-262_144:]
	}
	return string(output), code, runErr
}

func runDNSLookup(target string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupHost(ctx, target)
	if err != nil {
		return err.Error(), -1, err
	}
	output := fmt.Sprintf("%s resolves to:\n", target)
	for _, address := range addresses {
		output += "  " + address + "\n"
	}
	return output, 0, nil
}

func runPortCheck(target string, port int) (string, int, error) {
	address := net.JoinHostPort(target, strconv.Itoa(port))
	started := time.Now()
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	elapsed := time.Since(started)
	if err != nil {
		return fmt.Sprintf("%s: closed or unreachable (%s): %s", address, elapsed.Round(time.Millisecond), err), 1, nil
	}
	_ = conn.Close()
	return fmt.Sprintf("%s: open (connected in %s)", address, elapsed.Round(time.Millisecond)), 0, nil
}
