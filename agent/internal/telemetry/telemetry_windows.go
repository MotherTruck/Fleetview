package telemetry

import (
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	"fleetview-agent/internal/model"
)

// GlobalMemoryStatusEx, GetSystemTimes, and GetPerformanceInfo are not
// wrapped by golang.org/x/sys/windows, so they're bound directly here the
// same way that package binds everything else internally: a LazyDLL/LazyProc
// pair per call. Struct layouts follow the documented Win32 ABI, which has
// been stable across Windows versions.
var (
	modkernel32              = windows.NewLazySystemDLL("kernel32.dll")
	modpsapi                 = windows.NewLazySystemDLL("psapi.dll")
	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemTimes       = modkernel32.NewProc("GetSystemTimes")
	procGetPerformanceInfo   = modpsapi.NewProc("GetPerformanceInfo")
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

// performanceInformation mirrors PSAPI's PERFORMANCE_INFORMATION. The SIZE_T
// fields are page counts, not bytes; PageSize converts them.
type performanceInformation struct {
	cb                uint32
	_                 uint32 // padding: aligns the following SIZE_T fields to 8 bytes on amd64
	commitTotal       uintptr
	commitLimit       uintptr
	commitPeak        uintptr
	physicalTotal     uintptr
	physicalAvailable uintptr
	systemCache       uintptr
	kernelTotal       uintptr
	kernelPaged       uintptr
	kernelNonpaged    uintptr
	pageSize          uintptr
	handleCount       uint32
	processCount      uint32
	threadCount       uint32
}

func rootPath() string {
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	return drive + `\`
}

func readCPU() (cpuCounters, error) {
	var idle, kernel, user windows.Filetime
	r, _, err := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if r == 0 {
		return cpuCounters{}, fmt.Errorf("GetSystemTimes: %w", err)
	}
	idleTicks := filetimeTicks(idle)
	// Windows reports kernel time inclusive of idle time, so kernel+user is
	// the total and idle is already a subset of it (matching /proc/stat's
	// idle-is-part-of-total shape that percentCPU expects).
	totalTicks := filetimeTicks(kernel) + filetimeTicks(user)
	return cpuCounters{total: totalTicks, idle: idleTicks}, nil
}

func filetimeTicks(ft windows.Filetime) uint64 {
	return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
}

func readNetwork() (networkCounters, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return networkCounters{}, fmt.Errorf("list network interfaces: %w", err)
	}
	result := networkCounters{}
	for _, iface := range interfaces {
		var row windows.MibIfRow
		row.Index = uint32(iface.Index)
		if err := windows.GetIfEntry(&row); err != nil {
			continue
		}
		if row.Type == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		result.receive += uint64(row.InOctets)
		result.transmit += uint64(row.OutOctets)
	}
	return result, nil
}

func readMemory() (total, available, swapTotal, swapFree uint64) {
	var m memoryStatusEx
	m.length = uint32(unsafe.Sizeof(m))
	r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	if r == 0 {
		return 0, 0, 0, 0
	}
	total = m.totalPhys
	available = m.availPhys

	var perf performanceInformation
	perf.cb = uint32(unsafe.Sizeof(perf))
	r, _, _ = procGetPerformanceInfo.Call(uintptr(unsafe.Pointer(&perf)), uintptr(perf.cb))
	if r == 0 || perf.pageSize == 0 {
		return total, available, 0, 0
	}
	pageSize := uint64(perf.pageSize)
	physicalTotal := uint64(perf.physicalTotal) * pageSize
	physicalAvailable := uint64(perf.physicalAvailable) * pageSize
	commitTotal := uint64(perf.commitTotal) * pageSize
	commitLimit := uint64(perf.commitLimit) * pageSize

	// Best-effort approximation: Windows doesn't expose a distinct "swap used"
	// counter. Commit limit is physical RAM plus the page file, so subtracting
	// RAM out of both the limit and the current commit approximates page-file
	// total/used the way Task Manager's "Committed" figure implies it.
	swapTotal = subtractFloor(commitLimit, physicalTotal)
	physicalUsed := subtractFloor(physicalTotal, physicalAvailable)
	swapUsed := subtractFloor(commitTotal, physicalUsed)
	swapFree = subtractFloor(swapTotal, swapUsed)
	return total, available, swapTotal, swapFree
}

func readDisk(path string) (uint64, uint64) {
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

// readDisks lists every drive letter Windows actually reports, not just the
// system drive -- GetLogicalDrives returns a bitmask (bit N set means drive
// letter 'A'+N exists). DRIVE_REMOVABLE (USB) and DRIVE_FIXED (internal/
// external HDD/SSD) are both included since both are real, mounted drives;
// DRIVE_CDROM (usually empty, and GetDiskFreeSpaceEx fails on it when it is)
// and DRIVE_REMOTE (a network share, not a local drive) are not.
func readDisks() []model.Disk {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var disks []model.Disk
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		rootPtr, err := windows.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		driveType := windows.GetDriveType(rootPtr)
		if driveType != windows.DRIVE_FIXED && driveType != windows.DRIVE_REMOVABLE {
			continue
		}
		total, available := readDisk(root)
		if total == 0 {
			continue
		}
		disks = append(disks, model.Disk{
			MountPoint: root,
			UsedBytes:  subtractFloor(total, available),
			TotalBytes: total,
		})
	}
	return disks
}

// readLoad has no meaningful equivalent on Windows: there is no load-average
// concept (moving-average of the run queue) the way Unix schedulers expose
// one. CPUPercent already covers instantaneous CPU pressure.
func readLoad() (float64, float64, float64) {
	return 0, 0, 0
}

// readTemperature has no flat Win32 API; genuine sensor reads need WMI
// (MSAcpi_ThermalZoneTemperature), which many OEMs don't implement reliably.
// Left unimplemented for now, matching how the Linux side already returns
// nil when no sensor is found.
func readTemperature() *float64 {
	return nil
}

func processCount() int {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0
	}
	count := 0
	for {
		count++
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return count
}

func uptimeSeconds() uint64 {
	return uint64(windows.DurationSinceBoot().Seconds())
}
