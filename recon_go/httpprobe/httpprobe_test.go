package main

import (
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"
)

func TestHTTPProbe_ProbeURLStatusAndTime(t *testing.T) {
    html := "<html><head><title>Example</title></head><body>hello</body></html>"
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html")
        _, _ = w.Write([]byte(html))
    }))
    defer server.Close()

    result := probeURL(server.URL, 5*time.Second)

    if result.StatusCode != http.StatusOK {
        t.Fatalf("expected status 200, got %d", result.StatusCode)
    }
    if result.ResponseTime <= 0 {
        t.Fatalf("expected response time > 0, got %f", result.ResponseTime)
    }
    if result.Title != "Example" {
        t.Fatalf("expected title 'Example', got %q", result.Title)
    }
    if result.ContentLength != int64(len(html)) {
        t.Fatalf("expected content length %d, got %d", len(html), result.ContentLength)
    }
}

func TestExtractTitle(t *testing.T) {
    html := "<html><head><title>Foo Bar</title></head><body>body</body></html>"
    title := extractTitle(strings.NewReader(html))
    if title != "Foo Bar" {
        t.Fatalf("expected title 'Foo Bar', got %q", title)
    }
}
