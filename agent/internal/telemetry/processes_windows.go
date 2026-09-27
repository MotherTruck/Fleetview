package telemetry

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"fleetview-agent/internal/model"
)

// GetProcessMemoryInfo (PSAPI) is not wrapped by golang.org/x/sys/windows,
// so it's bound the same flat LazyDLL/LazyProc way as the rest of this
// package's Windows-specific calls (see telemetry_windows.go, which already
// declares modpsapi).
var procGetProcessMemoryInfo = modpsapi.NewProc("GetProcessMemoryInfo")

// processMemoryCounters mirrors PSAPI's PROCESS_MEMORY_COUNTERS.
// WorkingSetSize is the closest Windows equivalent to Linux's RSS: physical
// memory currently mapped for this process.
type processMemoryCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
}

type processSnapshot struct {
	ticks uint64
	at    time.Time
}

// ProcessSampler tracks each PID's cumulative CPU ticks across calls so
// CPUPercent can be computed as a delta, the same pattern telemetry.Collector
// already uses for the system-wide CPU counter.
type ProcessSampler struct {
	previous map[uint32]processSnapshot
}

func NewProcessSampler() *ProcessSampler {
	return &ProcessSampler{previous: map[uint32]processSnapshot{}}
}

// Sample enumerates every process via a Toolhelp32 snapshot, the same API
// processCount() in telemetry_windows.go already uses. Processes this agent
// can't open (most commonly a handful of protected system processes when
// not running as SYSTEM) are silently skipped rather than erroring -- this
// is a best-effort inventory signal, not something that can fail a metrics
// tick.
func (s *ProcessSampler) Sample() []model.ResourceConsumer {
	now := time.Now()
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil
	}

	current := make(map[uint32]processSnapshot)
	var result []model.ResourceConsumer
	for {
		pid := entry.ProcessID
		name := windows.UTF16ToString(entry.ExeFile[:])
		if ticks, memBytes, ok := readProcessUsage(pid); ok {
			current[pid] = processSnapshot{ticks: ticks, at: now}
			var cpuPercent float64
			if prev, existed := s.previous[pid]; existed {
				elapsed := now.Sub(prev.at).Seconds()
				if elapsed > 0 && ticks >= prev.ticks {
					// Filetime ticks are 100ns units; 1e7 of them make a second.
					cpuPercent = float64(ticks-prev.ticks) / 1e7 / elapsed * 100
				}
			}
			result = append(result, model.ResourceConsumer{
				Kind: "process", PID: int(pid), Name: name,
				CPUPercent: cpuPercent, MemoryBytes: memBytes,
			})
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	s.previous = current
	return result
}

func readProcessUsage(pid uint32) (ticks uint64, memBytes uint64, ok bool) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return 0, 0, false
	}
	defer windows.CloseHandle(handle)

	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return 0, 0, false
	}
	ticks = filetimeTicks(kernel) + filetimeTicks(user)

	var counters processMemoryCounters
	counters.cb = uint32(unsafe.Sizeof(counters))
	r, _, _ := procGetProcessMemoryInfo.Call(uintptr(handle), uintptr(unsafe.Pointer(&counters)), uintptr(counters.cb))
	if r != 0 {
		memBytes = uint64(counters.workingSetSize)
	}
	return ticks, memBytes, true
}
