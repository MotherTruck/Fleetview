package telemetry

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"fleetview-agent/internal/model"
)

// ProcessSampler reports FreeBSD's own per-process %cpu/rss directly from
// `ps`, rather than tracking cumulative CPU ticks across calls the way the
// Linux /proc-based sampler does: ps's %cpu column is already a decayed,
// kernel-computed instantaneous rate (see proc(4)/ps(1)), so there's
// nothing to delta here.
type ProcessSampler struct{}

func NewProcessSampler() *ProcessSampler {
	return &ProcessSampler{}
}

func (s *ProcessSampler) Sample() []model.ResourceConsumer {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// -o pid,%cpu,rss,comm= with a bare "=" header suppresses ps's column
	// headers, so every line is pure data -- comm can't contain
	// whitespace, so SplitN(4) is unnecessary; a 4-field line is always
	// exactly one process.
	output, err := exec.CommandContext(ctx, "ps", "-axo", "pid=,pcpu=,rss=,comm=").Output()
	if err != nil {
		return nil
	}
	var result []model.ResourceConsumer
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		cpuPercent, _ := strconv.ParseFloat(fields[1], 64)
		rssKB, _ := strconv.ParseUint(fields[2], 10, 64)
		result = append(result, model.ResourceConsumer{
			Kind: "process", PID: pid, Name: fields[3],
			CPUPercent: cpuPercent, MemoryBytes: rssKB * 1024,
		})
	}
	return result
}
