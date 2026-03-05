package main

import "testing"

func TestPortScanner(t *testing.T) {
    got := ScanPorts()
    if got == nil {
        t.Fatal("expected non-nil result")
    }
}
