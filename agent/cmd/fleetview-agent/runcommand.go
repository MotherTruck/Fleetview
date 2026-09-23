package main

import (
	"context"
	"os/exec"
	"runtime"
	"time"
)

// runCommand executes an ad-hoc admin-supplied command with the agent
// service's own privileges. Unlike the custom-installer bundle path, there
// are no files involved: this is a single command string run directly.
func runCommand(parent context.Context, command string) (string, int, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Minute)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command)
	} else {
		cmd = exec.CommandContext(ctx, "bash", "-c", command)
	}
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
	if len(output) > 1_048_576 {
		output = output[len(output)-1_048_576:]
	}
	return string(output), code, runErr
}
