package main

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestValidDiagnosticTarget(t *testing.T) {
	valid := []string{"example.com", "192.168.1.1", "localhost", "a", "a.b.c.d-e"}
	for _, target := range valid {
		if !validDiagnosticTarget.MatchString(target) {
			t.Errorf("expected %q to be a valid target", target)
		}
	}
	invalid := []string{"-c", "--flag=1", "; rm -rf /", "$(whoami)", "", "target with spaces", strings.Repeat("a", 260)}
	for _, target := range invalid {
		if validDiagnosticTarget.MatchString(target) {
			t.Errorf("expected %q to be rejected", target)
		}
	}
}

func TestRunNetworkDiagnosticRejectsInvalidTarget(t *testing.T) {
	_, code, err := runNetworkDiagnostic(context.Background(), "dns", "-malicious", 0)
	if err == nil {
		t.Fatal("expected an error for an invalid target")
	}
	if code != -1 {
		t.Errorf("expected exit code -1, got %d", code)
	}
}

func TestRunDNSLookupLocalhost(t *testing.T) {
	output, code, err := runDNSLookup("localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(output, "127.0.0.1") && !strings.Contains(output, "::1") {
		t.Errorf("expected localhost to resolve to a loopback address, got: %s", output)
	}
}

func TestRunDNSLookupUnresolvable(t *testing.T) {
	_, code, err := runDNSLookup("this-host-should-not-exist.invalid")
	if err == nil {
		t.Fatal("expected a resolution error")
	}
	if code != -1 {
		t.Errorf("expected exit code -1, got %d", code)
	}
}

func TestRunPortCheckOpenAndClosed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(listener.Addr().String())
	openPort, _ := strconv.Atoi(portStr)

	output, code, err := runPortCheck("127.0.0.1", openPort)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 0 {
		t.Errorf("expected an open port to report exit code 0, got %d: %s", code, output)
	}
	if !strings.Contains(output, "open") {
		t.Errorf("expected output to mention 'open', got: %s", output)
	}

	// Port 1 is reserved (tcpmux) and essentially never listening in a test
	// environment; connecting to a closed port on localhost fails fast.
	output, code, err = runPortCheck("127.0.0.1", 1)
	if err != nil {
		t.Fatalf("unexpected error (a closed port is reported via exit code, not err): %v", err)
	}
	if code != 1 {
		t.Errorf("expected a closed port to report exit code 1, got %d: %s", code, output)
	}
}

func TestParseMACAddress(t *testing.T) {
	cases := map[string][]byte{
		"aa:bb:cc:dd:ee:ff": {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		"AA-BB-CC-DD-EE-FF": {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		"aabb.ccdd.eeff":    {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	for input, expected := range cases {
		got, err := parseMACAddress(input)
		if err != nil {
			t.Fatalf("parseMACAddress(%q) unexpected error: %v", input, err)
		}
		if string(got) != string(expected) {
			t.Errorf("parseMACAddress(%q) = %x, want %x", input, got, expected)
		}
	}
	if _, err := parseMACAddress("not-a-mac"); err == nil {
		t.Error("expected an error for an invalid MAC address")
	}
}
