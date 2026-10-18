package inventory

import (
	"context"
	"os"
	"os/exec"
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
		return System{}, err
	}
	osName, osVersion := opnsenseVersion()
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
		OSName:       osName,
		OSVersion:    osVersion,
		Architecture: runtime.GOARCH,
		Details:      details,
	}, nil
}

// opnsenseVersion reports "OPNsense"/its product version when the
// OPNsense-specific version file is present, falling back to plain
// "FreeBSD"/the kernel release on bare FreeBSD (or an OPNsense install
// where that file ever moves) -- the same firstNonEmpty-style fallback
// chain inventory_linux.go uses for /etc/os-release.
func opnsenseVersion() (string, string) {
	if data, err := os.ReadFile("/usr/local/opnsense/version/opnsense"); err == nil {
		version := strings.TrimSpace(string(data))
		if version != "" {
			return "OPNsense", version
		}
	}
	return "FreeBSD", kernelRelease()
}

// kernelRelease shells out to sysctl rather than using syscall.Uname:
// unlike Linux, FreeBSD's standard "syscall" package exposes no Uname
// wrapper at all.
func kernelRelease() string {
	return sysctlOutput("kern.osrelease")
}

func cpuModel() string {
	return sysctlOutput("hw.model")
}

func sysctlOutput(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "sysctl", "-n", name).Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

func memoryStats() (uint64, uint64) {
	pageSize, _ := strconv.ParseUint(sysctlOutput("hw.pagesize"), 10, 64)
	total, _ := strconv.ParseUint(sysctlOutput("hw.physmem"), 10, 64)
	freePages, _ := strconv.ParseUint(sysctlOutput("vm.stats.vm.v_free_count"), 10, 64)
	inactivePages, _ := strconv.ParseUint(sysctlOutput("vm.stats.vm.v_inactive_count"), 10, 64)
	if pageSize == 0 {
		pageSize = 4096
	}
	return total, (freePages + inactivePages) * pageSize
}

func diskStats(path string) (uint64, uint64) {
	var stats syscall.Statfs_t
	if syscall.Statfs(path, &stats) != nil {
		return 0, 0
	}
	blockSize := uint64(stats.Bsize)
	bavail := stats.Bavail
	if bavail < 0 {
		bavail = 0
	}
	return stats.Blocks * blockSize, uint64(bavail) * blockSize
}

func loadAverages() (float64, float64, float64) {
	raw := strings.Trim(sysctlOutput("vm.loadavg"), "{} ")
	fields := strings.Fields(raw)
	if len(fields) < 3 {
		return 0, 0, 0
	}
	load1, _ := strconv.ParseFloat(fields[0], 64)
	load5, _ := strconv.ParseFloat(fields[1], 64)
	load15, _ := strconv.ParseFloat(fields[2], 64)
	return load1, load5, load15
}

func uptimeSeconds() uint64 {
	raw := sysctlOutput("kern.boottime")
	idx := strings.Index(raw, "sec = ")
	if idx == -1 {
		return 0
	}
	raw = raw[idx+len("sec = "):]
	comma := strings.IndexByte(raw, ',')
	if comma == -1 {
		return 0
	}
	bootSeconds, err := strconv.ParseInt(strings.TrimSpace(raw[:comma]), 10, 64)
	if err != nil || bootSeconds <= 0 {
		return 0
	}
	uptime := time.Now().Unix() - bootSeconds
	if uptime < 0 {
		return 0
	}
	return uint64(uptime)
}
