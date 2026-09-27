package telemetry

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"fleetview-agent/internal/model"
)

// clockTicksPerSecond is USER_HZ, the unit /proc/[pid]/stat's utime/stime
// fields are counted in. It's configurable in the kernel but has been 100 on
// every mainstream Linux distribution for decades; reading the real value
// needs sysconf(_SC_CLK_TCK), which isn't reachable without cgo.
const clockTicksPerSecond = 100

type processSnapshot struct {
	ticks uint64
	at    time.Time
}

// ProcessSampler tracks each PID's cumulative CPU ticks across calls so
// CPUPercent can be computed as a delta, the same pattern telemetry.Collector
// already uses for the system-wide CPU counter.
type ProcessSampler struct {
	previous map[int]processSnapshot
}

func NewProcessSampler() *ProcessSampler {
	return &ProcessSampler{previous: map[int]processSnapshot{}}
}

// Sample returns every process currently visible under /proc. Kernel threads
// and processes this agent can't read (a different user's, in the rare case
// it's not running as root) are silently skipped rather than erroring --
// this is a best-effort inventory signal, not something that can fail a
// metrics tick.
func (s *ProcessSampler) Sample() []model.ResourceConsumer {
	now := time.Now()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	current := make(map[int]processSnapshot, len(entries))
	result := make([]model.ResourceConsumer, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		ticks, name, ok := readProcStat(pid)
		if !ok {
			continue
		}
		current[pid] = processSnapshot{ticks: ticks, at: now}
		var cpuPercent float64
		if prev, existed := s.previous[pid]; existed {
			elapsed := now.Sub(prev.at).Seconds()
			if elapsed > 0 && ticks >= prev.ticks {
				cpuPercent = float64(ticks-prev.ticks) / clockTicksPerSecond / elapsed * 100
			}
		}
		result = append(result, model.ResourceConsumer{
			Kind: "process", PID: pid, Name: name,
			CPUPercent: cpuPercent, MemoryBytes: readProcRSS(pid),
		})
	}
	s.previous = current
	return result
}

// readProcStat parses /proc/[pid]/stat. The comm field (process name) is
// wrapped in parens and can itself contain spaces or parens, so it's
// extracted by the first "(" and the *last* ")" rather than field-splitting,
// matching how ps/top parse this file.
func readProcStat(pid int) (ticks uint64, name string, ok bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, "", false
	}
	text := string(data)
	open := strings.IndexByte(text, '(')
	closeParen := strings.LastIndexByte(text, ')')
	if open < 0 || closeParen < open {
		return 0, "", false
	}
	name = text[open+1 : closeParen]
	// Everything after the comm field, starting at proc(5) field 3 (state).
	fields := strings.Fields(text[closeParen+1:])
	// utime is field 14, stime is field 15; since fields[0] is field 3, that's indices 11 and 12.
	if len(fields) < 13 {
		return 0, "", false
	}
	utime, err1 := strconv.ParseUint(fields[11], 10, 64)
	stime, err2 := strconv.ParseUint(fields[12], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, "", false
	}
	return utime + stime, name, true
}

func readProcRSS(pid int) uint64 {
	file, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				return kb * 1024
			}
		}
		break
	}
	return 0
}
