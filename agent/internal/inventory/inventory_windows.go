package inventory

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"fleetview-agent/internal/containers"
)

// GlobalMemoryStatusEx and GetDiskFreeSpaceEx are also bound in the telemetry
// package; duplicated here rather than exported cross-package, matching how
// the Linux build already reads /proc/meminfo independently in both packages.
var (
	modkernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")
)

type memoryStatusEx struct {
	length               uint32
	memoryLoad           uint32
	totalPhys            uint64
	availPhys            uint64
	totalPageFile        uint64
	availPageFile        uint64
	totalVirtual         uint64
	availVirtual         uint64
	availExtendedVirtual uint64
}

func Collect(dockerInventoryEnabled bool) (System, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return System{}, fmt.Errorf("hostname: %w", err)
	}
	osName, osVersion := windowsVersion()
	memoryTotal, memoryAvailable := memoryStats()
	diskTotal, diskAvailable := diskStats(rootPath())
	load1, load5, load15 := loadAverages()
	details := map[string]interface{}{
		"kernel":                    osVersion,
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
		"uptime_seconds":            uint64(windows.DurationSinceBoot().Seconds()),
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
	} else {
		details["docker_available"] = false
		details["docker_containers"] = []containers.Container{}
	}
	return System{
		Hostname:     hostname,
		OSName:       osName,
		OSVersion:    osVersion,
		Architecture: runtime.GOARCH,
		Details:      details,
	}, nil
}

// windowsVersion reads the human-readable OS name and version from the
// registry rather than GetVersionEx/RtlGetVersion: GetVersionEx is subject to
// an application-compatibility shim that lies to unmanifested processes, and
// the registry values are what Windows' own Settings app displays.
func windowsVersion() (name string, version string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows", "unknown"
	}
	defer key.Close()
	productName, _, _ := key.GetStringValue("ProductName")
	displayVersion, _, _ := key.GetStringValue("DisplayVersion")
	if displayVersion == "" {
		displayVersion, _, _ = key.GetStringValue("ReleaseId")
	}
	buildNumber, _, _ := key.GetStringValue("CurrentBuildNumber")

	name = firstNonEmpty(productName, "Windows")
	switch {
	case displayVersion != "" && buildNumber != "":
		version = fmt.Sprintf("%s (Build %s)", displayVersion, buildNumber)
	case buildNumber != "":
		version = "Build " + buildNumber
	default:
		version = firstNonEmpty(displayVersion, "unknown")
	}
	return name, version
}

func cpuModel() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE)
	if err != nil {
		return "unknown"
	}
	defer key.Close()
	name, _, err := key.GetStringValue("ProcessorNameString")
	if err != nil || name == "" {
		return "unknown"
	}
	return name
}

func memoryStats() (uint64, uint64) {
	var m memoryStatusEx
	m.length = uint32(unsafe.Sizeof(m))
	r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	if r == 0 {
		return 0, 0
	}
	return m.totalPhys, m.availPhys
}

func diskStats(path string) (uint64, uint64) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0
	}
	var freeAvailable, totalBytes, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(pathPtr, &freeAvailable, &totalBytes, &totalFree); err != nil {
		return 0, 0
	}
	return totalBytes, freeAvailable
}

// loadAverages has no Windows equivalent; see the identical note in the
// telemetry package's readLoad.
func loadAverages() (float64, float64, float64) {
	return 0, 0, 0
}

func rootPath() string {
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	return drive + `\`
}
