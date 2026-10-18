package telemetry

import "testing"

func TestParseFloatPointerHandlesNVIDIASentinels(t *testing.T) {
	for _, value := range []string{"", "N/A", "n/a", "[Not Supported]", "garbage"} {
		if got := parseFloatPointer(value); got != nil {
			t.Errorf("parseFloatPointer(%q) = %v, want nil", value, *got)
		}
	}
	got := parseFloatPointer(" 42.5 ")
	if got == nil || *got != 42.5 {
		t.Errorf("parseFloatPointer(\" 42.5 \") = %v, want 42.5", got)
	}
}

func TestMebibytesPointerConvertsToBytes(t *testing.T) {
	got := mebibytesPointer("16384")
	if got == nil || *got != 16384*1024*1024 {
		t.Errorf("mebibytesPointer(\"16384\") = %v, want %d", got, uint64(16384*1024*1024))
	}
	if got := mebibytesPointer("N/A"); got != nil {
		t.Errorf("mebibytesPointer(\"N/A\") = %v, want nil", *got)
	}
}

func TestCollectGPUsAndProcessesDisabledReturnsEmpty(t *testing.T) {
	gpus, processes := collectGPUsAndProcesses(false)
	if len(gpus) != 0 || len(processes) != 0 {
		t.Errorf("expected empty results when disabled, got gpus=%v processes=%v", gpus, processes)
	}
}
