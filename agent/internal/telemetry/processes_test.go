package telemetry

import (
	"testing"

	"fleetview-agent/internal/model"
)

func TestTopConsumersMergesCPUAndMemoryWithoutDuplicates(t *testing.T) {
	all := []model.ResourceConsumer{
		{Kind: "process", PID: 1, Name: "cpu-hog", CPUPercent: 90, MemoryBytes: 10},
		{Kind: "process", PID: 2, Name: "mem-hog", CPUPercent: 1, MemoryBytes: 900},
		{Kind: "process", PID: 3, Name: "both-hog", CPUPercent: 80, MemoryBytes: 800},
		{Kind: "container", Name: "quiet-container", CPUPercent: 0, MemoryBytes: 5},
	}
	got := TopConsumers(all, 2)

	names := map[string]bool{}
	for _, c := range got {
		if names[c.Name] {
			t.Fatalf("duplicate entry for %q in result: %+v", c.Name, got)
		}
		names[c.Name] = true
	}
	if !names["cpu-hog"] {
		t.Error("expected top-CPU entry cpu-hog to be present")
	}
	if !names["mem-hog"] {
		t.Error("expected top-memory entry mem-hog to be present")
	}
	if !names["both-hog"] {
		t.Error("expected both-hog (top-2 in both dimensions) to be present")
	}
	if names["quiet-container"] {
		t.Error("quiet-container ranks last in both dimensions and should have been cut by the limit")
	}
}

func TestTopConsumersHandlesEmptyAndZeroLimit(t *testing.T) {
	if got := TopConsumers(nil, 5); len(got) != 0 {
		t.Errorf("expected empty result for nil input, got %+v", got)
	}
	if got := TopConsumers([]model.ResourceConsumer{{Name: "x"}}, 0); len(got) != 0 {
		t.Errorf("expected empty result for zero limit, got %+v", got)
	}
}
