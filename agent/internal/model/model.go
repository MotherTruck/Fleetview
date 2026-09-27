package model

import "time"

type State struct {
	DeviceID   string `json:"device_id"`
	AgentToken string `json:"agent_token"`
}

type Package struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture,omitempty"`
	Source       string `json:"source"`
}

type Update struct {
	Package          string `json:"package"`
	Identifier       string `json:"identifier,omitempty"`
	InstalledVersion string `json:"installed_version"`
	AvailableVersion string `json:"available_version"`
	SecurityUpdate   *bool  `json:"security_update,omitempty"`
	RebootRequired   *bool  `json:"reboot_required,omitempty"`
}

type ApprovedUpdate struct {
	Package string `json:"package"`
	Version string `json:"version"`
}

type Report struct {
	Hostname          string                 `json:"hostname"`
	Platform          string                 `json:"platform"`
	OSName            string                 `json:"os_name"`
	OSVersion         string                 `json:"os_version"`
	Architecture      string                 `json:"architecture"`
	PackageManager    string                 `json:"package_manager"`
	AgentVersion      string                 `json:"agent_version"`
	Inventory         map[string]interface{} `json:"inventory"`
	InstalledPackages []Package              `json:"installed_packages"`
	AvailableUpdates  []Update               `json:"available_updates"`
	ScannedAt         time.Time              `json:"scanned_at"`
}

type Vulnerability struct {
	VulnerabilityID  string   `json:"vulnerability_id"`
	Package          string   `json:"package"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     string   `json:"fixed_version"`
	Severity         string   `json:"severity"`
	Status           string   `json:"status"`
	Title            string   `json:"title"`
	PrimaryURL       string   `json:"primary_url"`
	References       []string `json:"references"`
	Target           string   `json:"target"`
}

type VulnerabilityReport struct {
	Scanner         string          `json:"scanner"`
	ScannerVersion  string          `json:"scanner_version"`
	ScannedAt       time.Time       `json:"scanned_at"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	ListeningPorts  []ListeningPort `json:"listening_ports"`
}

// ListeningPort is a process found bound to a network port at scan time,
// gathered alongside the vulnerability scan so the server can flag which
// vulnerable packages are actually network-facing versus only ever loaded
// as a library dependency.
type ListeningPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Process  string `json:"process"`
}

// ResourceConsumer is one entry in a MetricsReport's top-consumers list: a
// single host process or Docker container, whichever kind it is. PID is
// only meaningful for Kind == "process".
type ResourceConsumer struct {
	Kind        string  `json:"kind"`
	PID         int     `json:"pid,omitempty"`
	Name        string  `json:"name"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemoryBytes uint64  `json:"memory_bytes"`
}

type MetricsReport struct {
	RecordedAt           time.Time `json:"recorded_at"`
	CPUPercent           float64   `json:"cpu_percent"`
	MemoryUsedBytes      uint64    `json:"memory_used_bytes"`
	MemoryTotalBytes     uint64    `json:"memory_total_bytes"`
	SwapUsedBytes        uint64    `json:"swap_used_bytes"`
	SwapTotalBytes       uint64    `json:"swap_total_bytes"`
	DiskUsedBytes        uint64    `json:"disk_used_bytes"`
	DiskTotalBytes       uint64    `json:"disk_total_bytes"`
	Load1                float64   `json:"load_1"`
	Load5                float64   `json:"load_5"`
	Load15               float64   `json:"load_15"`
	NetworkReceiveBPS    float64   `json:"network_receive_bps"`
	NetworkTransmitBPS   float64   `json:"network_transmit_bps"`
	NetworkReceiveBytes  uint64    `json:"network_receive_bytes"`
	NetworkTransmitBytes uint64    `json:"network_transmit_bytes"`
	ProcessCount         int       `json:"process_count"`
	TemperatureCelsius   *float64  `json:"temperature_celsius,omitempty"`
	UptimeSeconds        uint64    `json:"uptime_seconds"`
	GPUs                 []GPU     `json:"gpus"`
	TopConsumers         []ResourceConsumer `json:"top_consumers"`
}

type GPU struct {
	Index              string   `json:"index"`
	Name               string   `json:"name"`
	Vendor             string   `json:"vendor"`
	UtilizationPercent *float64 `json:"utilization_percent,omitempty"`
	MemoryUsedBytes    *uint64  `json:"memory_used_bytes,omitempty"`
	MemoryTotalBytes   *uint64  `json:"memory_total_bytes,omitempty"`
	TemperatureCelsius *float64 `json:"temperature_celsius,omitempty"`
	PowerWatts         *float64 `json:"power_watts,omitempty"`
}

type AgentSettings struct {
	MetricsIntervalSeconds   int  `json:"metrics_interval_seconds"`
	InventoryIntervalSeconds int  `json:"inventory_interval_seconds"`
	GPUMonitoringEnabled     bool `json:"gpu_monitoring_enabled"`
	DockerInventoryEnabled   bool `json:"docker_inventory_enabled"`
}

type Job struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"type"`
	Options map[string]interface{} `json:"options"`
}

type JobResult struct {
	Status   string `json:"status"`
	ExitCode *int   `json:"exit_code"`
	Output   string `json:"output"`
	Error    string `json:"error"`
}
