package telemetry

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestProcessSamplerFindsRealBusyProcess spins up a genuine CPU-burning
// subprocess and verifies the sampler (which shells out to nothing --
// pure /proc reads) actually finds it with a non-trivial CPU% and non-zero
// memory, across two real samples a second apart (the first sample per PID
// has no prior tick to diff against, so CPUPercent is 0 on it by design).
func TestProcessSamplerFindsRealBusyProcess(t *testing.T) {
	cmd := exec.Command("sh", "-c", "while true; do :; done")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start busy process: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	sampler := NewProcessSampler()
	sampler.Sample() // prime: first sample has no delta to compute CPU% from
	time.Sleep(1200 * time.Millisecond)
	second := sampler.Sample()

	var found bool
	var cpuPercent float64
	var memBytes uint64
	for _, p := range second {
		if p.PID == cmd.Process.Pid {
			found = true
			cpuPercent = p.CPUPercent
			memBytes = p.MemoryBytes
		}
	}
	if !found {
		t.Fatalf("busy process pid %d not found in sample of %d processes", cmd.Process.Pid, len(second))
	}
	if cpuPercent <= 0 {
		t.Errorf("expected CPU%% > 0 for a busy-loop process, got %v", cpuPercent)
	}
	if memBytes == 0 {
		t.Errorf("expected non-zero RSS, got 0")
	}
	t.Logf("busy pid %d: cpu=%.1f%% mem=%d bytes (own pid %d)", cmd.Process.Pid, cpuPercent, memBytes, os.Getpid())
}
