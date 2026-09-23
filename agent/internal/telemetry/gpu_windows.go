package telemetry

import "fleetview-agent/internal/model"

// collectVendorGPUs covers AMD/Intel GPU telemetry on Linux via sysfs; there
// is no equivalent flat Win32 API (real-time utilization needs the PDH
// "GPU Engine" counter set, a follow-up piece). NVIDIA is unaffected since
// collectNVIDIAGPUs shells out to nvidia-smi, which also ships for Windows.
func collectVendorGPUs() []model.GPU {
	return []model.GPU{}
}
