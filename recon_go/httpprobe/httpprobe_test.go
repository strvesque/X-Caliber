package main

import "testing"

func TestHTTPProbe(t *testing.T) {
    got := ProbeHTTP()
    if got == nil {
        t.Fatal("expected non-nil result")
    }
}
