package telemetry

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"fleetview-agent/internal/model"
)

// collectVendorGPUs reports AMD and Intel GPUs via the kernel's DRM sysfs
// interface. NVIDIA is excluded here since collectNVIDIAGPUs (nvidia-smi)
// supplies more accurate data and would otherwise duplicate the device.
func collectVendorGPUs() []model.GPU {
	cards, _ := filepath.Glob("/sys/class/drm/card[0-9]*")
	result := []model.GPU{}
	for _, card := range cards {
		index := strings.TrimPrefix(filepath.Base(card), "card")
		if _, err := strconv.Atoi(index); err != nil {
			continue
		}
		device := filepath.Join(card, "device")
		vendorCode := strings.ToLower(readText(filepath.Join(device, "vendor")))
		vendor := ""
		switch vendorCode {
		case "0x1002":
			vendor = "AMD"
		case "0x8086":
			vendor = "Intel"
		case "0x10de":
			continue
		default:
			continue
		}
		name := fmt.Sprintf("%s GPU (card%s)", vendor, index)
		utilization := readFloatPointer(filepath.Join(device, "gpu_busy_percent"), 1)
		memoryUsed := readUintPointer(filepath.Join(device, "mem_info_vram_used"))
		memoryTotal := readUintPointer(filepath.Join(device, "mem_info_vram_total"))
		temperature := drmTemperature(device)
		result = append(result, model.GPU{
			Index: index, Name: name, Vendor: vendor, UtilizationPercent: utilization,
			MemoryUsedBytes: memoryUsed, MemoryTotalBytes: memoryTotal, TemperatureCelsius: temperature,
		})
	}
	return result
}

func drmTemperature(device string) *float64 {
	paths, _ := filepath.Glob(filepath.Join(device, "hwmon", "hwmon*", "temp1_input"))
	for _, path := range paths {
		if value := readFloatPointer(path, 1000); value != nil && *value > 0 && *value < 150 {
			return value
		}
	}
	return nil
}

func readText(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readFloatPointer(path string, divisor float64) *float64 {
	value, err := strconv.ParseFloat(readText(path), 64)
	if err != nil {
		return nil
	}
	value /= divisor
	return &value
}

func readUintPointer(path string) *uint64 {
	value, err := strconv.ParseUint(readText(path), 10, 64)
	if err != nil {
		return nil
	}
	return &value
}
