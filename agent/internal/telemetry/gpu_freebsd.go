package telemetry

import "fleetview-agent/internal/model"

// collectVendorGPUs always reports no GPUs on FreeBSD: this agent targets
// OPNsense, a headless firewall/router appliance with no desktop GPU to
// report. gpu.go's own collectNVIDIAGPUs() (nvidia-smi-based) still runs
// first and works unmodified if it's ever present, exactly as on Linux.
func collectVendorGPUs() []model.GPU {
	return nil
}
