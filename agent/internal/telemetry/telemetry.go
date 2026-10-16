package telemetry

import (
	"time"

	"fleetview-agent/internal/model"
)

type cpuCounters struct {
	total uint64
	idle  uint64
}

type networkCounters struct {
	receive  uint64
	transmit uint64
}

type Collector struct {
	previousCPU     cpuCounters
	previousNetwork networkCounters
	previousAt      time.Time
	primed          bool
}

func NewCollector() *Collector {
	return &Collector{}
}

// Prime captures the counters needed to calculate rates without delaying startup.
func (c *Collector) Prime() error {
	cpu, err := readCPU()
	if err != nil {
		return err
	}
	network, err := readNetwork()
	if err != nil {
		return err
	}
	c.previousCPU = cpu
	c.previousNetwork = network
	c.previousAt = time.Now()
	c.primed = true
	return nil
}

func (c *Collector) Collect(gpuMonitoringEnabled bool) (model.MetricsReport, error) {
	now := time.Now()
	cpu, err := readCPU()
	if err != nil {
		return model.MetricsReport{}, err
	}
	network, err := readNetwork()
	if err != nil {
		return model.MetricsReport{}, err
	}
	if !c.primed {
		c.previousCPU = cpu
		c.previousNetwork = network
		c.previousAt = now
		c.primed = true
	}

	cpuPercent := percentCPU(c.previousCPU, cpu)
	elapsed := now.Sub(c.previousAt).Seconds()
	receiveBPS, transmitBPS := networkRates(c.previousNetwork, network, elapsed)
	c.previousCPU = cpu
	c.previousNetwork = network
	c.previousAt = now

	memoryTotal, memoryAvailable, swapTotal, swapFree := readMemory()
	diskTotal, diskAvailable := readDisk(rootPath())
	disks := readDisks()
	load1, load5, load15 := readLoad()
	temperature := readTemperature()

	return model.MetricsReport{
		RecordedAt:           now.UTC(),
		CPUPercent:           cpuPercent,
		MemoryUsedBytes:      subtractFloor(memoryTotal, memoryAvailable),
		MemoryTotalBytes:     memoryTotal,
		SwapUsedBytes:        subtractFloor(swapTotal, swapFree),
		SwapTotalBytes:       swapTotal,
		DiskUsedBytes:        subtractFloor(diskTotal, diskAvailable),
		DiskTotalBytes:       diskTotal,
		Load1:                load1,
		Load5:                load5,
		Load15:               load15,
		NetworkReceiveBPS:    receiveBPS,
		NetworkTransmitBPS:   transmitBPS,
		NetworkReceiveBytes:  network.receive,
		NetworkTransmitBytes: network.transmit,
		ProcessCount:         processCount(),
		TemperatureCelsius:   temperature,
		UptimeSeconds:        uptimeSeconds(),
		GPUs:                 collectGPUs(gpuMonitoringEnabled),
		Disks:                disks,
	}, nil
}

func percentCPU(previous, current cpuCounters) float64 {
	if current.total <= previous.total || current.idle < previous.idle {
		return 0
	}
	totalDelta := current.total - previous.total
	idleDelta := current.idle - previous.idle
	if totalDelta == 0 || idleDelta > totalDelta {
		return 0
	}
	return clampPercent(float64(totalDelta-idleDelta) * 100 / float64(totalDelta))
}

func networkRates(previous, current networkCounters, seconds float64) (float64, float64) {
	if seconds <= 0 || current.receive < previous.receive || current.transmit < previous.transmit {
		return 0, 0
	}
	return float64(current.receive-previous.receive) / seconds, float64(current.transmit-previous.transmit) / seconds
}

func subtractFloor(total, available uint64) uint64 {
	if available > total {
		return 0
	}
	return total - available
}

func clampPercent(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}
