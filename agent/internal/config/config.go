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

// UpdateServerURL rewrites the FLEETVIEW_SERVER_URL line of the config
// file at path in place (replacing it if present, appending it
// otherwise), used by a MIGRATE_SERVER job to permanently re-point this
// agent at a new management server. Every other line -- including the
// enrollment token, which a device re-pointed to a freshly migrated
// server doesn't need again -- is preserved exactly as written.
func UpdateServerURL(path, newURL string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	replaced := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "FLEETVIEW_SERVER_URL=") || strings.HasPrefix(trimmed, "#FLEETVIEW_SERVER_URL=") {
			lines[i] = fmt.Sprintf("FLEETVIEW_SERVER_URL=%s", newURL)
			replaced = true
			break
		}
	}
	if !replaced {
		lines = append(lines, fmt.Sprintf("FLEETVIEW_SERVER_URL=%s", newURL))
	}
	info, err := os.Stat(path)
	mode := os.FileMode(0600)
	if err == nil {
		mode = info.Mode()
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), mode)
}
