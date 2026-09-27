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
	ServerURL        string
	EnrollmentToken  string
	StatePath        string
	ScanInterval     time.Duration
	MetricsInterval  time.Duration
	JobPollInterval  time.Duration
	RequestTimeout   time.Duration
	AllowInsecureTLS bool
	CAFile           string
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
	parseSeconds := func(key string, fallback int) time.Duration {
		value, err := strconv.Atoi(lookup(key, strconv.Itoa(fallback)))
		if err != nil || value < 1 {
			value = fallback
		}
		return time.Duration(value) * time.Second
	}
	allowInsecure, _ := strconv.ParseBool(lookup("FLEETVIEW_ALLOW_INSECURE_TLS", "false"))
	result := Config{
		ServerURL:        strings.TrimRight(lookup("FLEETVIEW_SERVER_URL", "http://127.0.0.1:8080"), "/"),
		EnrollmentToken:  lookup("FLEETVIEW_ENROLLMENT_TOKEN", ""),
		StatePath:        lookup("FLEETVIEW_STATE_PATH", defaultStatePath()),
		ScanInterval:     parseSeconds("FLEETVIEW_SCAN_INTERVAL_SECONDS", 900),
		MetricsInterval:  parseSeconds("FLEETVIEW_METRICS_INTERVAL_SECONDS", 60),
		JobPollInterval:  parseSeconds("FLEETVIEW_JOB_POLL_SECONDS", 10),
		RequestTimeout:   parseSeconds("FLEETVIEW_REQUEST_TIMEOUT_SECONDS", 60),
		AllowInsecureTLS: allowInsecure,
		CAFile:           lookup("FLEETVIEW_CA_FILE", ""),
	}
	if result.ServerURL == "" {
		return Config{}, fmt.Errorf("FLEETVIEW_SERVER_URL is required")
	}
	return result, nil
}
