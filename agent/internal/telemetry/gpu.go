package telemetry

import (
	"context"
	"encoding/csv"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"fleetview-agent/internal/model"
)

func collectGPUs(enabled bool) []model.GPU {
	if !enabled {
		return []model.GPU{}
	}
	result := collectNVIDIAGPUs()
	result = append(result, collectVendorGPUs()...)
	return result
}

func collectNVIDIAGPUs() []model.GPU {
	if _, err := exec.LookPath("nvidia-smi"); err != nil {
		return []model.GPU{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "nvidia-smi",
		"--query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw",
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
		if len(record) < 7 {
			continue
		}
		utilization := parseFloatPointer(record[2])
		memoryUsed := mebibytesPointer(record[3])
		memoryTotal := mebibytesPointer(record[4])
		temperature := parseFloatPointer(record[5])
		power := parseFloatPointer(record[6])
		result = append(result, model.GPU{
			Index: strings.TrimSpace(record[0]), Name: strings.TrimSpace(record[1]), Vendor: "NVIDIA",
			UtilizationPercent: utilization, MemoryUsedBytes: memoryUsed, MemoryTotalBytes: memoryTotal,
			TemperatureCelsius: temperature, PowerWatts: power,
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
