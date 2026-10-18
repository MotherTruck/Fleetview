package inventory

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"fleetview-agent/internal/containers"
	"fleetview-agent/internal/screen"
)

func Collect(dockerInventoryEnabled bool) (System, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return System{}, fmt.Errorf("hostname: %w", err)
	}
	osRelease := readKeyValues("/etc/os-release")
	memoryTotal, memoryAvailable := memoryStats()
	diskTotal, diskAvailable := diskStats("/")
	load1, load5, load15 := loadAverages()
	details := map[string]interface{}{
		"kernel":                    kernelRelease(),
		"cpu_model":                 cpuModel(),
		"logical_cpus":              runtime.NumCPU(),
		"load_1":                    load1,
		"load_5":                    load5,
		"load_15":                   load15,
		"memory_bytes":              memoryTotal,
		"memory_available_bytes":    memoryAvailable,
		"memory_used_bytes":         subtractFloor(memoryTotal, memoryAvailable),
		"root_disk_total_bytes":     diskTotal,
		"root_disk_available_bytes": diskAvailable,
		"root_disk_used_bytes":      subtractFloor(diskTotal, diskAvailable),
		"ip_addresses":              ipAddresses(),
		"mac_addresses":             macAddresses(),
		"uptime_seconds":            uptimeSeconds(),
		"remote_control":            screen.Detect(),
	}
	if dockerInventoryEnabled {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		dockerAvailable, dockerContainers, dockerErr := containers.Collect(ctx)
		cancel()
		details["docker_available"] = dockerAvailable
		details["docker_containers"] = dockerContainers
		if dockerErr != nil {
			details["docker_error"] = dockerErr.Error()
		}
		volumeCtx, volumeCancel := context.WithTimeout(context.Background(), 6*time.Second)
		_, dockerVolumes, _ := containers.CollectVolumes(volumeCtx)
		volumeCancel()
		details["docker_volumes"] = dockerVolumes
	} else {
		details["docker_available"] = false
		details["docker_containers"] = []containers.Container{}
		details["docker_volumes"] = []containers.Volume{}
	}
	return System{
		Hostname:     hostname,
		OSName:       firstNonEmpty(osRelease["PRETTY_NAME"], osRelease["NAME"], "Linux"),
		OSVersion:    firstNonEmpty(osRelease["VERSION_ID"], osRelease["BUILD_ID"], osRelease["VERSION"], "unknown"),
		Architecture: runtime.GOARCH,
		Details:      details,
	}, nil
}

func readKeyValues(path string) map[string]string {
	result := map[string]string{}
	file, err := os.Open(path)
	if err != nil {
		return result
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok {
			result[key] = strings.Trim(value, `"`)
		}
	}
	return result
}

func kernelRelease() string {
	var data syscall.Utsname
	if syscall.Uname(&data) != nil {
		return "unknown"
	}
	buffer := make([]byte, 0, len(data.Release))
	for _, value := range data.Release {
		if value == 0 {
			break
		}
		buffer = append(buffer, byte(value))
	}
	return string(buffer)
}

func cpuModel() string {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "unknown"
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if ok && strings.TrimSpace(key) == "model name" {
			return strings.TrimSpace(value)
		}
	}
	return "unknown"
}

func memoryStats() (uint64, uint64) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer file.Close()
	var total, available uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = value * 1024
		case "MemAvailable:":
			available = value * 1024
		}
	}
	return total, available
}

func diskStats(path string) (uint64, uint64) {
	var stats syscall.Statfs_t
	if syscall.Statfs(path, &stats) != nil {
		return 0, 0
	}
	blockSize := uint64(stats.Bsize)
	return stats.Blocks * blockSize, stats.Bavail * blockSize
}

func loadAverages() (float64, float64, float64) {
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
