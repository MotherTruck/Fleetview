package telemetry

import (
	"bytes"
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"fleetview-agent/internal/model"
)

func rootPath() string { return "/" }

// sysctlOutput runs `sysctl -n <name>` and returns its trimmed stdout, or
// "" if the OID doesn't exist (e.g. a sensor sysctl on hardware without
// one) -- callers treat an empty result as "unavailable", not an error,
// since metrics collection on a device missing one optional sensor
// shouldn't fail the whole report.
func sysctlOutput(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "sysctl", "-n", name).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func readCPU() (cpuCounters, error) {
	// kern.cp_time reports five jiffies-style aggregate counters: user,
	// nice, system, interrupt, idle (see FreeBSD's <sys/resource.h>
	// CP_USER..CP_IDLE). Same shape as /proc/stat's "cpu" line on Linux,
	// just a fixed five fields with no label prefix to skip.
	raw := sysctlOutput("kern.cp_time")
	fields := strings.Fields(raw)
	if len(fields) != 5 {
		return cpuCounters{}, nil
	}
	values := make([]uint64, 5)
	for i, field := range fields {
		values[i], _ = strconv.ParseUint(field, 10, 64)
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	return cpuCounters{total: total, idle: values[4]}, nil
}

// netstatIfaceLine matches one `netstat -ibn` data row for a non-loopback
// link-layer interface: name, mtu, "<Link#N>", address, Ipkts, Ierrs,
// Idrop, Ibytes, Opkts, Oerrs, Obytes, Coll[, Drop]. Field positions vary
// slightly by FreeBSD version, so this keys off the two byte-count
// columns (7th/11th) by position within the Link rows specifically,
// skipping the duplicate per-protocol (inet/inet6) rows netstat also
// prints for the same interface.
var netstatLinkLine = regexp.MustCompile(`^(\S+)\s+\d+\s+<Link[^>]*>\s+\S+\s+(\d+)\s+\d+\s+\d+\s+(\d+)\s+(\d+)\s+\d+\s+(\d+)`)

func readNetwork() (networkCounters, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "netstat", "-ibn").Output()
	if err != nil {
		return networkCounters{}, nil
	}
	result := networkCounters{}
	for _, line := range strings.Split(string(output), "\n") {
		match := netstatLinkLine.FindStringSubmatch(line)
		if match == nil || match[1] == "lo0" {
			continue
		}
		receive, _ := strconv.ParseUint(match[3], 10, 64)
		transmit, _ := strconv.ParseUint(match[5], 10, 64)
		result.receive += receive
		result.transmit += transmit
	}
	return result, nil
}

func readMemory() (uint64, uint64, uint64, uint64) {
	pageSize, _ := strconv.ParseUint(sysctlOutput("hw.pagesize"), 10, 64)
	total, _ := strconv.ParseUint(sysctlOutput("hw.physmem"), 10, 64)
	freePages, _ := strconv.ParseUint(sysctlOutput("vm.stats.vm.v_free_count"), 10, 64)
	inactivePages, _ := strconv.ParseUint(sysctlOutput("vm.stats.vm.v_inactive_count"), 10, 64)
	if pageSize == 0 {
		pageSize = 4096
	}
	// "Available" approximates Linux's MemAvailable: free pages plus
	// inactive (reclaimable-without-swapping) pages, both reported by
	// the VM subsystem in page units.
	available := (freePages + inactivePages) * pageSize

	var swapTotal, swapUsed uint64
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "swapinfo", "-k").Output(); err == nil {
		for _, line := range strings.Split(string(output), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			kTotal, _ := strconv.ParseUint(fields[1], 10, 64)
			kUsed, _ := strconv.ParseUint(fields[2], 10, 64)
			swapTotal += kTotal * 1024
			swapUsed += kUsed * 1024
		}
	}
	swapFree := subtractFloor(swapTotal, swapUsed)
	return total, available, swapTotal, swapFree
}

func readDisk(path string) (uint64, uint64) {
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

// pseudoFilesystems mirrors telemetry_linux.go's list for the FreeBSD
// mount table: virtual/kernel filesystems `mount -p` lists right
// alongside real, device-backed drives.
var pseudoFilesystems = map[string]bool{
	"devfs": true, "fdescfs": true, "procfs": true, "linprocfs": true,
	"linsysfs": true, "tmpfs": true, "nullfs": true, "unionfs": true,
}

const maxDisks = 64

func readDisks() []model.Disk {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// `mount -p` prints one machine-parsable, tab-separated line per
	// mount: special-device, mount-point, fstype, options, dump, pass --
	// the same information /proc/mounts gives on Linux, in a format meant
	// for scripts rather than `mount`'s plain human-readable output.
	output, err := exec.CommandContext(ctx, "mount", "-p").Output()
	if err != nil {
		return nil
	}
	var disks []model.Disk
	for _, line := range strings.Split(string(output), "\n") {
		if len(disks) >= maxDisks {
			break
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		device, mountPoint, fsType := fields[0], fields[1], fields[2]
		if pseudoFilesystems[fsType] {
			continue
		}
		total, available := readDisk(mountPoint)
		if total == 0 {
			continue
		}
		disks = append(disks, model.Disk{
			MountPoint: mountPoint,
			Device:     device,
			Filesystem: fsType,
			UsedBytes:  subtractFloor(total, available),
			TotalBytes: total,
		})
	}
	return disks
}

func readLoad() (float64, float64, float64) {
	// vm.loadavg prints as "{ 0.12 0.08 0.05 }" (a struct loadavg, FreeBSD's
	// sysctl pretty-printer wraps it in braces).
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

func readTemperature() *float64 {
	// dev.cpu.0.temperature (coretemp(4)/amdtemp(4)) is the common sensor
	// path on real hardware; absent entirely on most virtualized OPNsense
	// deployments, where this just stays nil like a headless Linux VM.
	raw := sysctlOutput("dev.cpu.0.temperature")
	if raw == "" {
		return nil
	}
	raw = strings.TrimSuffix(raw, "C")
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value <= 0 || value >= 150 {
		return nil
	}
	return &value
}

func processCount() int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "ps", "-axo", "pid=").Output()
	if err != nil {
		return 0
	}
	return len(bytes.Fields(output))
}

func uptimeSeconds() uint64 {
	// kern.boottime prints as "{ sec = 1700000000, usec = 0 } Mon Jan ...".
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
