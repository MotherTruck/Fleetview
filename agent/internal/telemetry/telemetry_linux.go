package telemetry

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func rootPath() string { return "/" }

func readCPU() (cpuCounters, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return cpuCounters{}, fmt.Errorf("read cpu counters: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return cpuCounters{}, fmt.Errorf("read cpu counters: missing aggregate cpu line")
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuCounters{}, fmt.Errorf("read cpu counters: unexpected /proc/stat format")
	}
	values := make([]uint64, 0, len(fields)-1)
	for _, field := range fields[1:] {
		value, parseErr := strconv.ParseUint(field, 10, 64)
		if parseErr != nil {
			return cpuCounters{}, fmt.Errorf("read cpu counters: %w", parseErr)
		}
		values = append(values, value)
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	return cpuCounters{total: total, idle: idle}, nil
}

func readNetwork() (networkCounters, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return networkCounters{}, fmt.Errorf("read network counters: %w", err)
	}
	defer file.Close()
	result := networkCounters{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		name, counters, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) == "lo" {
			continue
		}
		fields := strings.Fields(counters)
		if len(fields) < 9 {
			continue
		}
		receive, receiveErr := strconv.ParseUint(fields[0], 10, 64)
		transmit, transmitErr := strconv.ParseUint(fields[8], 10, 64)
		if receiveErr == nil {
			result.receive += receive
		}
		if transmitErr == nil {
			result.transmit += transmit
		}
	}
	if err := scanner.Err(); err != nil {
		return networkCounters{}, fmt.Errorf("read network counters: %w", err)
	}
	return result, nil
}

func readMemory() (uint64, uint64, uint64, uint64) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, 0
	}
	defer file.Close()
	values := map[string]uint64{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr == nil {
			values[fields[0]] = value * 1024
		}
	}
	return values["MemTotal:"], values["MemAvailable:"], values["SwapTotal:"], values["SwapFree:"]
}

func readDisk(path string) (uint64, uint64) {
	var stats syscall.Statfs_t
	if syscall.Statfs(path, &stats) != nil {
		return 0, 0
	}
	blockSize := uint64(stats.Bsize)
	return stats.Blocks * blockSize, stats.Bavail * blockSize
}

func readLoad() (float64, float64, float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	load1, _ := strconv.ParseFloat(fields[0], 64)
	load5, _ := strconv.ParseFloat(fields[1], 64)
	load15, _ := strconv.ParseFloat(fields[2], 64)
	return load1, load5, load15
}

func readTemperature() *float64 {
	hwmons, _ := filepath.Glob("/sys/class/hwmon/hwmon*")
	for _, hwmon := range hwmons {
		nameData, err := os.ReadFile(filepath.Join(hwmon, "name"))
		if err != nil {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(string(nameData)))
		if name != "coretemp" && name != "k10temp" && name != "zenpower" {
			continue
		}
		inputs, _ := filepath.Glob(filepath.Join(hwmon, "temp*_input"))
		for _, input := range inputs {
			if value := temperatureValue(input); value != nil {
				return value
			}
		}
	}
	zones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*")
	for _, zone := range zones {
		typeData, err := os.ReadFile(filepath.Join(zone, "type"))
		if err != nil {
			continue
		}
		zoneType := strings.ToLower(strings.TrimSpace(string(typeData)))
		if !strings.Contains(zoneType, "cpu") && !strings.Contains(zoneType, "pkg") && !strings.Contains(zoneType, "package") {
			continue
		}
		if value := temperatureValue(filepath.Join(zone, "temp")); value != nil {
			return value
		}
	}
	return nil
}

func temperatureValue(path string) *float64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
	if err != nil {
		return nil
	}
	if value > 1000 {
		value /= 1000
	}
	if value <= 0 || value >= 150 {
		return nil
	}
	return &value
}

func processCount() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err == nil {
			count++
		}
	}
	return count
}

func uptimeSeconds() uint64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	value, _ := strconv.ParseFloat(fields[0], 64)
	return uint64(value)
}
