package telemetry

import "testing"

func TestPercentCPU(t *testing.T) {
	previous := cpuCounters{total: 1000, idle: 700}
	current := cpuCounters{total: 1200, idle: 800}
	if got := percentCPU(previous, current); got != 50 {
		t.Fatalf("percentCPU() = %v, want 50", got)
	}
}

func TestNetworkRates(t *testing.T) {
	previous := networkCounters{receive: 1000, transmit: 2000}
	current := networkCounters{receive: 1600, transmit: 3200}
	receive, transmit := networkRates(previous, current, 2)
	if receive != 300 || transmit != 600 {
		t.Fatalf("networkRates() = %v, %v; want 300, 600", receive, transmit)
	}
}

func TestCountersReset(t *testing.T) {
	receive, transmit := networkRates(
		networkCounters{receive: 2000, transmit: 3000},
		networkCounters{receive: 100, transmit: 100},
		1,
	)
	if receive != 0 || transmit != 0 {
		t.Fatalf("networkRates() after reset = %v, %v; want 0, 0", receive, transmit)
	}
}
