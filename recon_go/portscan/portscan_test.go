package main

import (
	"encoding/json"
	"testing"
	"time"
)

// TestScanPort tests single port scanning
func TestScanPort(t *testing.T) {
	// Test closed port
	result := scanPort("127.0.0.1", 9999, 500*time.Millisecond)
	if result.State != "closed" && result.State != "filtered" {
		t.Errorf("expected closed/filtered port, got %s", result.State)
	}
	if result.Port != 9999 {
		t.Errorf("expected port 9999, got %d", result.Port)
	}
	if result.Protocol != "tcp" {
		t.Errorf("expected protocol tcp, got %s", result.Protocol)
	}

	// Note: Testing open ports would require a running service
	// CI environment may have open ports on localhost (e.g., 22, 80)
}

// TestScanPorts tests concurrent port scanning
func TestScanPorts(t *testing.T) {
	// Scan a small range including common and uncommon ports
	ports := []int{22, 80, 443, 9999, 9998}
	results := scanPorts("127.0.0.1", ports, 5, 500*time.Millisecond)

	// Results should be non-nil
	if results == nil {
		t.Fatal("expected non-nil results")
	}

	// Should return only open ports
	for _, r := range results {
		if r.State != "open" {
			t.Errorf("expected only open ports in results, got state=%s for port %d", r.State, r.Port)
		}
	}
}

// TestDetectService tests service detection
func TestDetectService(t *testing.T) {
	tests := []struct {
		port     int
		expected string
	}{
		{22, "ssh"},
		{80, "http"},
		{443, "https"},
		{3306, "mysql"},
		{5432, "postgresql"},
		{6379, "redis"},
		{27017, "mongodb"},
		{3389, "rdp"},
		{8080, "http-proxy"},
		{9999, "unknown"},
	}

	for _, tt := range tests {
		got := detectService(tt.port)
		if got != tt.expected {
			t.Errorf("detectService(%d) = %s, want %s", tt.port, got, tt.expected)
		}
	}
}

// TestParsePortRange tests port range parsing
func TestParsePortRange(t *testing.T) {
	tests := []struct {
		input    string
		expected []int
		hasError bool
	}{
		{"1-5", []int{1, 2, 3, 4, 5}, false},
		{"80", []int{80}, false},
		{"22,80,443", []int{22, 80, 443}, false},
		{"1-3,5,7-9", []int{1, 2, 3, 5, 7, 8, 9}, false},
		{"invalid", nil, true},
		{"80-22", nil, true}, // Invalid range (start > end)
		{"", nil, true},
	}

	for _, tt := range tests {
		got, err := parsePortRange(tt.input)
		if tt.hasError {
			if err == nil {
				t.Errorf("parsePortRange(%q) expected error, got nil", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePortRange(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if len(got) != len(tt.expected) {
			t.Errorf("parsePortRange(%q) length = %d, want %d", tt.input, len(got), len(tt.expected))
			continue
		}
		for i, p := range got {
			if p != tt.expected[i] {
				t.Errorf("parsePortRange(%q)[%d] = %d, want %d", tt.input, i, p, tt.expected[i])
			}
		}
	}
}

// TestScanResult tests ScanResult structure and JSON marshaling
func TestScanResult(t *testing.T) {
	result := ScanResult{
		Target: "127.0.0.1",
		OpenPorts: []PortResult{
			{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"},
			{Port: 80, Protocol: "tcp", State: "open", Service: "http"},
		},
		ScanTime:  2.5,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Test JSON marshaling
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal ScanResult: %v", err)
	}

	// Test JSON unmarshaling
	var decoded ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal ScanResult: %v", err)
	}

	// Verify fields
	if decoded.Target != result.Target {
		t.Errorf("Target = %s, want %s", decoded.Target, result.Target)
	}
	if len(decoded.OpenPorts) != len(result.OpenPorts) {
		t.Errorf("OpenPorts length = %d, want %d", len(decoded.OpenPorts), len(result.OpenPorts))
	}
	if decoded.ScanTime != result.ScanTime {
		t.Errorf("ScanTime = %f, want %f", decoded.ScanTime, result.ScanTime)
	}
}

// TestWorkerPoolConcurrency tests that worker pool respects concurrency limits
func TestWorkerPoolConcurrency(t *testing.T) {
	// Create 200 ports to scan
	ports := make([]int, 200)
	for i := range ports {
		ports[i] = 9000 + i
	}

	// Scan with max 10 workers
	start := time.Now()
	results := scanPorts("127.0.0.1", ports, 10, 100*time.Millisecond)
	duration := time.Since(start)

	// With 10 workers and 100ms timeout, scanning 200 ports should take roughly:
	// 200 ports / 10 workers * 100ms = ~2 seconds (plus overhead)
	// Allow up to 5 seconds for CI variability
	if duration > 5*time.Second {
		t.Errorf("scan took too long: %v (expected <5s with 10 workers)", duration)
	}

	// Results should be non-nil (even if empty - all ports likely closed)
	if results == nil {
		t.Fatal("expected non-nil results")
	}
}

// TestGetTopPorts tests common port list generation
func TestGetTopPorts(t *testing.T) {
	tests := []struct {
		count    int
		expected int // expected number of ports returned
	}{
		{10, 10},
		{100, 100},
		{1000, 1000},
		{10000, 1000}, // Max 1000 ports available
		{0, 0},
	}

	for _, tt := range tests {
		got := getTopPorts(tt.count)
		if len(got) != tt.expected {
			t.Errorf("getTopPorts(%d) returned %d ports, want %d", tt.count, len(got), tt.expected)
		}

		// Verify ports are unique
		seen := make(map[int]bool)
		for _, port := range got {
			if seen[port] {
				t.Errorf("getTopPorts(%d) contains duplicate port: %d", tt.count, port)
			}
			seen[port] = true
		}
	}
}

// TestConcurrentScanPerformance tests scanning performance
func TestConcurrentScanPerformance(t *testing.T) {
	// Scan 100 closed ports with 50 workers
	ports := make([]int, 100)
	for i := range ports {
		ports[i] = 9000 + i
	}

	start := time.Now()
	scanPorts("127.0.0.1", ports, 50, 200*time.Millisecond)
	duration := time.Since(start)

	// With 50 workers, 100 ports should complete in roughly 2 batches
	// 200ms timeout * 2 batches = ~400ms (plus overhead)
	// Allow up to 2 seconds for CI
	if duration > 2*time.Second {
		t.Errorf("concurrent scan too slow: %v (expected <2s)", duration)
	}
}

// TestPortResultValidation tests PortResult field requirements
func TestPortResultValidation(t *testing.T) {
	result := PortResult{
		Port:     80,
		Protocol: "tcp",
		State:    "open",
		Service:  "http",
	}

	// Marshal to JSON
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal PortResult: %v", err)
	}

	// Unmarshal and verify required fields
	var decoded PortResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal PortResult: %v", err)
	}

	if decoded.Port != 80 {
		t.Errorf("Port = %d, want 80", decoded.Port)
	}
	if decoded.Protocol != "tcp" {
		t.Errorf("Protocol = %s, want tcp", decoded.Protocol)
	}
	if decoded.State != "open" {
		t.Errorf("State = %s, want open", decoded.State)
	}
	if decoded.Service != "http" {
		t.Errorf("Service = %s, want http", decoded.Service)
	}
}

// Legacy test compatibility
func TestPortScanner(t *testing.T) {
	got := ScanPorts()
	if got == nil {
		t.Fatal("expected non-nil result")
	}
}
