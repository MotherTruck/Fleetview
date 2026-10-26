package containers

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"fleetview-agent/internal/model"
)

type Port struct {
	PrivatePort int    `json:"private_port"`
	PublicPort  int    `json:"public_port,omitempty"`
	Type        string `json:"type"`
	IP          string `json:"ip,omitempty"`
}

type Container struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Image     string `json:"image"`
	State     string `json:"state"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	Ports     []Port `json:"ports"`
	// Populated from the in-memory cache CheckForUpdate/ApplyUpdate leaves
	// behind (see update.go) -- never checked as part of an ordinary
	// inventory scan itself, since pulling every image on every scan would
	// be far too expensive to do on the regular scan interval. Omitted
	// entirely (rather than a default false/empty) until this container has
	// actually been checked at least once, so the server/dashboard can tell
	// "known up to date" apart from "never checked".
	UpdateAvailable *bool  `json:"update_available,omitempty"`
	UpdateCheckedAt string `json:"update_checked_at,omitempty"`
}

// withUpdateStatus merges any cached update-check result for item.ID into
// item's two update_available/update_checked_at fields -- called by each
// platform's Collect() so the status survives into the very next ordinary
// inventory report after a check, not just the job result of the check
// itself.
func withUpdateStatus(item Container) Container {
	status, ok := cachedUpdateStatus(item.ID)
	if !ok {
		return item
	}
	available := status.Available
	item.UpdateAvailable = &available
	item.UpdateCheckedAt = status.CheckedAt.Format(time.RFC3339)
	return item
}

type dockerStatsCPU struct {
	CPUUsage struct {
		TotalUsage uint64 `json:"total_usage"`
	} `json:"cpu_usage"`
	SystemCPUUsage uint64 `json:"system_cpu_usage"`
	OnlineCPUs     uint64 `json:"online_cpus"`
}

type dockerStatsMemory struct {
	Usage uint64 `json:"usage"`
	Stats struct {
		Cache        uint64 `json:"cache"`
		InactiveFile uint64 `json:"inactive_file"`
	} `json:"stats"`
}

type dockerStatsResponse struct {
	CPUStats    dockerStatsCPU    `json:"cpu_stats"`
	PreCPUStats dockerStatsCPU    `json:"precpu_stats"`
	MemoryStats dockerStatsMemory `json:"memory_stats"`
}

// CollectStats fetches a point-in-time CPU/memory snapshot for every running
// container, using Docker's own non-streaming stats endpoint. Unlike host
// process sampling, this needs no state kept between calls: each response
// independently carries both a current and a ~1-second-old CPU reading
// (cpu_stats/precpu_stats), which Docker computes internally.
func CollectStats(ctx context.Context) ([]model.ResourceConsumer, error) {
	available, list, err := Collect(ctx)
	if !available || err != nil {
		return nil, err
	}
	client := dockerClient()
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []model.ResourceConsumer
	)
	for _, item := range list {
		if item.State != "running" {
			continue
		}
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			consumer, ok := fetchOneStat(ctx, client, item)
			if !ok {
				return
			}
			mu.Lock()
			results = append(results, consumer)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results, nil
}

func fetchOneStat(ctx context.Context, client *http.Client, item Container) (model.ResourceConsumer, bool) {
	reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://docker/containers/"+item.ID+"/stats?stream=false", nil)
	if err != nil {
		return model.ResourceConsumer{}, false
	}
	response, err := client.Do(request)
	if err != nil {
		return model.ResourceConsumer{}, false
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return model.ResourceConsumer{}, false
	}
	var stats dockerStatsResponse
	if err := json.NewDecoder(response.Body).Decode(&stats); err != nil {
		return model.ResourceConsumer{}, false
	}
	memBytes := stats.MemoryStats.Usage
	if cache := stats.MemoryStats.Stats.Cache; cache > 0 && cache < memBytes {
		memBytes -= cache
	} else if inactive := stats.MemoryStats.Stats.InactiveFile; inactive > 0 && inactive < memBytes {
		memBytes -= inactive
	}
	return model.ResourceConsumer{Kind: "container", Name: item.Name, CPUPercent: dockerCPUPercent(stats), MemoryBytes: memBytes}, true
}

func dockerCPUPercent(stats dockerStatsResponse) float64 {
	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage) - float64(stats.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stats.CPUStats.SystemCPUUsage) - float64(stats.PreCPUStats.SystemCPUUsage)
	if cpuDelta <= 0 || systemDelta <= 0 {
		return 0
	}
	onlineCPUs := stats.CPUStats.OnlineCPUs
	if onlineCPUs == 0 {
		onlineCPUs = 1
	}
	return (cpuDelta / systemDelta) * float64(onlineCPUs) * 100
}
