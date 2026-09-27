package telemetry

import (
	"fmt"
	"sort"

	"fleetview-agent/internal/model"
)

// TopConsumers merges host processes and Docker containers into one list,
// keeping the top `limit` by CPU% and the top `limit` by memory
// (deduplicated) rather than a single blended ranking: a CPU-bound workload
// and a memory-bound one are usually different processes, and collapsing
// both into one score would hide whichever ranks lower on it.
func TopConsumers(all []model.ResourceConsumer, limit int) []model.ResourceConsumer {
	if limit <= 0 || len(all) == 0 {
		return []model.ResourceConsumer{}
	}
	byCPU := append([]model.ResourceConsumer(nil), all...)
	sort.Slice(byCPU, func(i, j int) bool { return byCPU[i].CPUPercent > byCPU[j].CPUPercent })
	if len(byCPU) > limit {
		byCPU = byCPU[:limit]
	}
	byMemory := append([]model.ResourceConsumer(nil), all...)
	sort.Slice(byMemory, func(i, j int) bool { return byMemory[i].MemoryBytes > byMemory[j].MemoryBytes })
	if len(byMemory) > limit {
		byMemory = byMemory[:limit]
	}

	seen := make(map[string]bool, len(byCPU)+len(byMemory))
	merged := make([]model.ResourceConsumer, 0, len(byCPU)+len(byMemory))
	for _, group := range [][]model.ResourceConsumer{byCPU, byMemory} {
		for _, consumer := range group {
			key := fmt.Sprintf("%s:%d:%s", consumer.Kind, consumer.PID, consumer.Name)
			if seen[key] {
				continue
			}
			seen[key] = true
			merged = append(merged, consumer)
		}
	}
	return merged
}
