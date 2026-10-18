package telemetry

import (
	"context"
	"encoding/csv"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"fleetview-agent/internal/model"
)

// nvidiaSMITimeout is generous beyond what a healthy, already-warm GPU needs
// (typically well under a second): a GPU that's been idle long enough to
// hit a power-saving state, or one behind virtualization/passthrough (e.g.
// a cloud VM's T4/A100), can take several seconds to wake up and answer its
// first query -- 5s was cutting that close enough to occasionally return no
// GPU data at all rather than a slow-but-correct one. collectGPUsAndProcesses
// below runs both nvidia-smi calls concurrently, so a slow/cold GPU costs at
// most one timeout's worth of stall on a metrics tick, not the sum of both.
const nvidiaSMITimeout = 8 * time.Second

// collectGPUsAndProcesses runs the GPU-card and per-process nvidia-smi
// queries concurrently (each independently bounded by nvidiaSMITimeout) so
// a slow/cold GPU adds at most one timeout's worth of latency to a single
// metrics tick, not two stacked.
func collectGPUsAndProcesses(enabled bool) ([]model.GPU, []model.GPUProcess) {
	if !enabled {
		return []model.GPU{}, []model.GPUProcess{}
	}
	var wg sync.WaitGroup
	var gpus []model.GPU
	var processes []model.GPUProcess
	wg.Add(2)
	go func() {
		defer wg.Done()
		gpus = collectNVIDIAGPUs()
		gpus = append(gpus, collectVendorGPUs()...)
	}()
	go func() {
		defer wg.Done()
		processes = collectNVIDIAProcesses()
	}()
	wg.Wait()
	return gpus, processes
}

func collectNVIDIAGPUs() []model.GPU {
	if _, err := exec.LookPath("nvidia-smi"); err != nil {
		return []model.GPU{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), nvidiaSMITimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "nvidia-smi",
		"--query-gpu=index,uuid,name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw",
		"--format=csv,noheader,nounits")
	output, err := command.Output()
	if err != nil {
		return []model.GPU{}
	}
	reader := csv.NewReader(strings.NewReader(string(output)))
	records, err := reader.ReadAll()
	if err != nil {
		return []model.GPU{}
	}
	result := make([]model.GPU, 0, len(records))
	for _, record := range records {
		if len(record) < 8 {
			continue
		}
		utilization := parseFloatPointer(record[3])
		memoryUsed := mebibytesPointer(record[4])
		memoryTotal := mebibytesPointer(record[5])
		temperature := parseFloatPointer(record[6])
		power := parseFloatPointer(record[7])
		result = append(result, model.GPU{
			Index: strings.TrimSpace(record[0]), UUID: strings.TrimSpace(record[1]),
			Name: strings.TrimSpace(record[2]), Vendor: "NVIDIA",
			UtilizationPercent: utilization, MemoryUsedBytes: memoryUsed, MemoryTotalBytes: memoryTotal,
			TemperatureCelsius: temperature, PowerWatts: power,
		})
	}
	return result
}

// collectNVIDIAProcesses lists every process currently holding GPU memory,
// via the same compute-apps query `nvidia-smi` itself uses for `nvidia-smi
// pmon`-style tooling. Unlike collectNVIDIAGPUs's fields, used_memory here
// has no "--nounits" equivalent gap to worry about: a process either holds
// memory (a number) or nvidia-smi doesn't list it at all.
func collectNVIDIAProcesses() []model.GPUProcess {
	if _, err := exec.LookPath("nvidia-smi"); err != nil {
		return []model.GPUProcess{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), nvidiaSMITimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "nvidia-smi",
		"--query-compute-apps=gpu_uuid,pid,process_name,used_memory",
		"--format=csv,noheader,nounits")
	output, err := command.Output()
	if err != nil {
		return []model.GPUProcess{}
	}
	reader := csv.NewReader(strings.NewReader(string(output)))
	records, err := reader.ReadAll()
	if err != nil {
		return []model.GPUProcess{}
	}
	result := make([]model.GPUProcess, 0, len(records))
	for _, record := range records {
		if len(record) < 4 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(record[1]))
		if err != nil {
			continue
		}
		memoryUsed := mebibytesPointer(record[3])
		if memoryUsed == nil {
			continue
		}
		result = append(result, model.GPUProcess{
			GPUUUID: strings.TrimSpace(record[0]), PID: pid,
			Name: strings.TrimSpace(record[2]), MemoryUsedBytes: *memoryUsed,
		})
	}
	return result
}

func parseFloatPointer(value string) *float64 {
	normalized := strings.TrimSpace(value)
	if normalized == "" || strings.EqualFold(normalized, "N/A") || normalized == "[Not Supported]" {
		return nil
	}
	parsed, err := strconv.ParseFloat(normalized, 64)
	if err != nil {
		return nil
	}
	return &parsed
}

func mebibytesPointer(value string) *uint64 {
	parsed := parseFloatPointer(value)
	if parsed == nil {
		return nil
	}
	bytes := uint64(*parsed * 1024 * 1024)
	return &bytes
}
