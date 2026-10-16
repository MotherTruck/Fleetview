package containers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"time"
)

// composeProjectPattern mirrors docker compose's own project-name rule
// (and the server's matching check in devices.rs's valid_compose_project):
// lowercase alphanumerics, '-' and '_', starting with an alphanumeric.
var composeProjectPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// maxComposeBytes matches devices.rs's MAX_COMPOSE_BYTES -- enforced again
// here since a job's options are whatever the server last validated them
// as, not something this process should trust blindly.
const maxComposeBytes = 256 * 1024

// maxComposeOutput bounds how much of `docker compose up`'s combined
// output is kept for the job result -- an image pull can be chatty, and
// only the tail (where a real failure's error message actually is) matters.
const maxComposeOutput = 8000

// composeTimeout is generous: `up` can mean pulling one or more images
// from scratch, which on a slow link can take minutes.
const composeTimeout = 10 * time.Minute

// ComposeUp writes compose to a temp file and runs `docker compose -p
// project -f <file> up -d --remove-orphans` against it. Requires the
// `docker compose` CLI plugin on the endpoint (bundled with any current
// Docker Engine/Desktop install) -- this shells out to it rather than
// talking to the Engine API directly because compose's whole job (multi-
// service orchestration, networks, dependency ordering) has no single
// equivalent REST endpoint to call instead.
func ComposeUp(ctx context.Context, project, compose string) (string, error) {
	if !composeProjectPattern.MatchString(project) {
		return "", fmt.Errorf("invalid Docker Compose project name")
	}
	if compose == "" || len(compose) > maxComposeBytes {
		return "", fmt.Errorf("compose file is empty or too large")
	}

	file, err := os.CreateTemp("", "fleetview-compose-*.yml")
	if err != nil {
		return "", fmt.Errorf("write compose file: %w", err)
	}
	defer os.Remove(file.Name())
	if _, err := file.WriteString(compose); err != nil {
		file.Close()
		return "", fmt.Errorf("write compose file: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("write compose file: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, composeTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "docker", "compose", "-p", project, "-f", file.Name(), "up", "-d", "--remove-orphans")
	output, runErr := cmd.CombinedOutput()
	trimmed := truncateComposeOutput(output)
	if runErr != nil {
		return "", fmt.Errorf("docker compose up: %w: %s", runErr, trimmed)
	}
	return trimmed, nil
}

func truncateComposeOutput(output []byte) string {
	if len(output) > maxComposeOutput {
		output = output[len(output)-maxComposeOutput:]
	}
	return string(output)
}
