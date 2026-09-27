package containers

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// TestCollectStatsRealDocker exercises CollectStats against a real, already
// running container -- not a mock -- verifying the actual HTTP client and
// JSON parsing path against Docker's genuine stats response shape. The
// caller is expected to have started a CPU-busy container named
// "fv-stress-test" beforehand; this test skips if Docker (or that
// container) isn't reachable, rather than failing CI environments that
// don't have a Docker daemon.
func TestCollectStatsRealDocker(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	available, list, err := Collect(ctx)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !available {
		t.Skip("Docker daemon not reachable")
	}
	found := false
	for _, c := range list {
		if c.Name == "fv-stress-test" && c.State == "running" {
			found = true
		}
	}
	if !found {
		t.Skip("fv-stress-test container is not running")
	}

	stats, err := CollectStats(ctx)
	if err != nil {
		t.Fatalf("CollectStats: %v", err)
	}
	var match *struct {
		cpu float64
		mem uint64
	}
	for _, s := range stats {
		if s.Kind == "container" && s.Name == "fv-stress-test" {
			match = &struct {
				cpu float64
				mem uint64
			}{s.CPUPercent, s.MemoryBytes}
		}
	}
	if match == nil {
		t.Fatalf("fv-stress-test not found in CollectStats result: %+v", stats)
	}
	if match.cpu <= 0 {
		t.Errorf("expected CPU%% > 0 for a busy-loop container, got %v", match.cpu)
	}
	if match.mem == 0 {
		t.Errorf("expected non-zero memory usage, got 0")
	}
	t.Logf("fv-stress-test: cpu=%.1f%% mem=%d bytes", match.cpu, match.mem)
}
