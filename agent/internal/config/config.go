package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ServerURL           string
	EnrollmentToken     string
	StatePath           string
	ScanInterval        time.Duration
	MetricsInterval     time.Duration
	JobPollInterval     time.Duration
	RequestTimeout      time.Duration
	AllowInsecureTLS    bool
}

func Load(path string) (Config, error) {
	values := map[string]string{}
	if file, err := os.Open(path); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if ok {
				values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
			}
		}
		if err := scanner.Err(); err != nil {
			return Config{}, fmt.Errorf("read config: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return Config{}, fmt.Errorf("open config: %w", err)
	}

	lookup := func(key, fallback string) string {
		if value := os.Getenv(key); value != "" {
			return value
		}
		if value := values[key]; value != "" {
			return value
		}
		return fallback
	}
	// lookupRenamed checks the current key first, then the pre-rename EPC_
	// name of the same setting, so an agent.env left over from an install
	// that predates the FleetView rename still works until it's updated.
	lookupRenamed := func(key, legacyKey, fallback string) string {
		return lookup(key, lookup(legacyKey, fallback))
	}
	parseSeconds := func(key, legacyKey string, fallback int) time.Duration {
		value, err := strconv.Atoi(lookupRenamed(key, legacyKey, strconv.Itoa(fallback)))
		if err != nil || value < 1 {
			value = fallback
		}
		return time.Duration(value) * time.Second
	}
	allowInsecure, _ := strconv.ParseBool(lookupRenamed("FLEETVIEW_ALLOW_INSECURE_TLS", "EPC_ALLOW_INSECURE_TLS", "false"))
	result := Config{
		ServerURL:        strings.TrimRight(lookupRenamed("FLEETVIEW_SERVER_URL", "EPC_SERVER_URL", "http://127.0.0.1:8080"), "/"),
		EnrollmentToken:  lookupRenamed("FLEETVIEW_ENROLLMENT_TOKEN", "EPC_ENROLLMENT_TOKEN", ""),
		StatePath:        lookupRenamed("FLEETVIEW_STATE_PATH", "EPC_STATE_PATH", defaultStatePath()),
		ScanInterval:     parseSeconds("FLEETVIEW_SCAN_INTERVAL_SECONDS", "EPC_SCAN_INTERVAL_SECONDS", 900),
		MetricsInterval:  parseSeconds("FLEETVIEW_METRICS_INTERVAL_SECONDS", "EPC_METRICS_INTERVAL_SECONDS", 60),
		JobPollInterval:  parseSeconds("FLEETVIEW_JOB_POLL_SECONDS", "EPC_JOB_POLL_SECONDS", 10),
		RequestTimeout:   parseSeconds("FLEETVIEW_REQUEST_TIMEOUT_SECONDS", "EPC_REQUEST_TIMEOUT_SECONDS", 60),
		AllowInsecureTLS: allowInsecure,
	}
	if result.ServerURL == "" {
		return Config{}, fmt.Errorf("FLEETVIEW_SERVER_URL is required")
	}
	return result, nil
}
