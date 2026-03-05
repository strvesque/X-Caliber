package main

import "testing"

func TestSubdomainEnumerator(t *testing.T) {
    got := EnumerateSubdomains()
    if got == nil {
        t.Fatal("expected non-nil result")
    }
}
