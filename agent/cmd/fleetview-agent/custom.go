package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"fleetview-agent/internal/client"
)

var safeBundleFilename = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,199}$`)
var safeBundleID = regexp.MustCompile(`^[a-f0-9-]{36}$`)

func runCustomInstall(parent context.Context, api *client.Client, jobID string) (string, int, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Minute)
	defer cancel()
	bundle, err := api.Bundle(ctx, jobID)
	if err != nil {
		return "", -1, err
	}
	if bundle.Platform != runtime.GOOS || len(bundle.Command) == 0 || len(bundle.Command) > 4096 || len(bundle.Files) == 0 || len(bundle.Files) > 5 {
		return "", -1, fmt.Errorf("invalid custom package manifest for this device")
	}
	dir, err := os.MkdirTemp("", "fleetview-bundle-")
	if err != nil {
		return "", -1, err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0700); err != nil {
		return "", -1, err
	}
	seen := map[string]bool{}
	for _, item := range bundle.Files {
		if !safeBundleID.MatchString(item.ID) || !safeBundleFilename.MatchString(item.Filename) || item.Filename == "." || item.Filename == ".." || seen[item.Filename] || item.Size < 1 || item.Size > 8*1024*1024 || len(item.SHA256) != 64 {
			return "", -1, fmt.Errorf("invalid bundle filename or size")
		}
		seen[item.Filename] = true
		data, downloadErr := api.BundleFile(ctx, jobID, item.ID)
		if downloadErr != nil {
			return "", -1, downloadErr
		}
		digest := sha256.Sum256(data)
		if len(data) != item.Size || hex.EncodeToString(digest[:]) != item.SHA256 {
			return "", -1, fmt.Errorf("bundle file checksum mismatch: %s", item.Filename)
		}
		if err := os.WriteFile(filepath.Join(dir, item.Filename), data, 0600); err != nil {
			return "", -1, err
		}
	}
	var command *exec.Cmd
	if runtime.GOOS == "windows" {
		command = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", bundle.Command)
	} else {
		command = exec.CommandContext(ctx, "bash", "-c", bundle.Command)
	}
	command.Dir = dir
	output, runErr := command.CombinedOutput()
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
