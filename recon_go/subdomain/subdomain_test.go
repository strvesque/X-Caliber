package main

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"
)

func TestNormalizeDomain(t *testing.T) {
    tests := []struct {
        input    string
        expected string
        ok       bool
    }{
        {"example.com", "example.com", true},
        {" EXAMPLE.COM ", "example.com", true},
        {"sub.example.com", "example.com", true},
        {"http://example.com", "example.com", true},
        {"https://sub.example.com/path", "example.com", true},
        {"", "", false},
        {"invalid domain", "", false},
    }

    for _, tt := range tests {
        got, ok := normalizeDomain(tt.input)
        if ok != tt.ok {
            t.Fatalf("normalizeDomain(%q) ok=%v, want %v", tt.input, ok, tt.ok)
        }
        if got != tt.expected {
            t.Fatalf("normalizeDomain(%q) = %q, want %q", tt.input, got, tt.expected)
        }
    }
}

func TestDeduplicateAndNormalize(t *testing.T) {
    input := []string{"A.EXAMPLE.COM", "b.example.com", "a.example.com", "b.example.com "}
    got := deduplicateAndNormalize(input)
    if len(got) != 2 {
        t.Fatalf("expected 2 unique subdomains, got %d", len(got))
    }
}

func TestParseCrtShResponse(t *testing.T) {
    jsonBody := `[
        {"common_name": "example.com", "name_value": "www.example.com\napi.example.com"},
        {"common_name": "shop.example.com", "name_value": "shop.example.com"}
    ]`
    subdomains, err := parseCrtShResponse(strings.NewReader(jsonBody), "example.com")
    if err != nil {
        t.Fatalf("parseCrtShResponse failed: %v", err)
    }
    if len(subdomains) != 3 {
        t.Fatalf("expected 3 subdomains, got %d", len(subdomains))
    }
}

func TestParseCrtShResponse_InvalidJSON(t *testing.T) {
    _, err := parseCrtShResponse(strings.NewReader("not json"), "example.com")
    if err == nil {
        t.Fatal("expected error for invalid JSON")
    }
}

func TestParseHackerTargetResponse(t *testing.T) {
    body := "www.example.com,93.184.216.34\napi.example.com,93.184.216.34\n"
    subdomains := parseHackerTargetResponse(strings.NewReader(body), "example.com")
    if len(subdomains) != 2 {
        t.Fatalf("expected 2 subdomains, got %d", len(subdomains))
    }
}

func TestParseDNSDumpsterResponse(t *testing.T) {
    html := `<td class="col-md-4">www.example.com</td><td class="col-md-4">api.example.com</td>`
    subdomains := parseDNSDumpsterResponse(strings.NewReader(html), "example.com")
    if len(subdomains) != 2 {
        t.Fatalf("expected 2 subdomains, got %d", len(subdomains))
    }
}

func TestEnumerateSubdomains_PartialFailures(t *testing.T) {
    crtServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        _, _ = w.Write([]byte(`[{"common_name":"example.com","name_value":"www.example.com"}]`))
    }))
    defer crtServer.Close()

    hackerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        _, _ = w.Write([]byte("api.example.com,93.184.216.34\n"))
    }))
    defer hackerServer.Close()

    cfg := ProviderConfig{
        CRTCrtShURL:     crtServer.URL,
        DNSDumpsterURL:  "http://127.0.0.1:1",
        HackerTargetURL: hackerServer.URL,
    }

    client := &http.Client{Timeout: 2 * time.Second}
    subdomains := enumerateSubdomains("example.com", client, cfg)
    if len(subdomains) != 2 {
        t.Fatalf("expected 2 subdomains, got %d", len(subdomains))
    }
}

func TestEnumerateSubdomains_AllFail(t *testing.T) {
    cfg := ProviderConfig{
        CRTCrtShURL:     "http://127.0.0.1:1",
        DNSDumpsterURL:  "http://127.0.0.1:1",
        HackerTargetURL: "http://127.0.0.1:1",
    }
    client := &http.Client{Timeout: 1 * time.Second}
    subdomains := enumerateSubdomains("example.com", client, cfg)
    if len(subdomains) != 0 {
        t.Fatalf("expected empty result, got %d", len(subdomains))
    }
}

func TestEnumerateSubdomains_Timeout(t *testing.T) {
    slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        time.Sleep(2 * time.Second)
        _, _ = w.Write([]byte(""))
    }))
    defer slowServer.Close()

    cfg := ProviderConfig{
        CRTCrtShURL:     slowServer.URL,
        DNSDumpsterURL:  slowServer.URL,
        HackerTargetURL: slowServer.URL,
    }
    client := &http.Client{Timeout: 300 * time.Millisecond}
    subdomains := enumerateSubdomains("example.com", client, cfg)
    if len(subdomains) != 0 {
        t.Fatalf("expected timeout result empty, got %d", len(subdomains))
    }
}

func TestOutputJSONSchema(t *testing.T) {
    output := SubdomainOutput{
        Target:     "example.com",
        Subdomains: []string{"a.example.com", "b.example.com"},
        Count:      2,
        Timestamp:  time.Now().UTC().Format(time.RFC3339),
    }

    data, err := json.Marshal(output)
    if err != nil {
        t.Fatalf("failed to marshal output: %v", err)
    }

    var decoded SubdomainOutput
    if err := json.Unmarshal(data, &decoded); err != nil {
        t.Fatalf("failed to unmarshal output: %v", err)
    }

    if decoded.Count != len(decoded.Subdomains) {
        t.Fatalf("count mismatch: %d vs %d", decoded.Count, len(decoded.Subdomains))
    }
}

func TestFetchProviderHandlesHTTPError(t *testing.T) {
    badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        http.Error(w, "boom", http.StatusInternalServerError)
    }))
    defer badServer.Close()

    client := &http.Client{Timeout: time.Second}
    _, err := fetchProvider(badServer.URL, client)
    if err == nil {
        t.Fatal("expected error for non-200 response")
    }
}

func TestFetchProvider_Timeout(t *testing.T) {
    slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        time.Sleep(2 * time.Second)
        _, _ = w.Write([]byte("ok"))
    }))
    defer slowServer.Close()

    client := &http.Client{Timeout: 200 * time.Millisecond}
    _, err := fetchProvider(slowServer.URL, client)
    if err == nil {
        t.Fatal("expected timeout error")
    }
}

func TestFetchProviderWithContext_Cancel(t *testing.T) {
    slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        time.Sleep(2 * time.Second)
        _, _ = w.Write([]byte("ok"))
    }))
    defer slowServer.Close()

    client := &http.Client{Timeout: time.Second}
    ctx, cancel := context.WithCancel(context.Background())
    cancel()
    _, err := fetchProviderWithContext(ctx, slowServer.URL, client)
    if err == nil {
        t.Fatal("expected context cancellation error")
    }
}

func TestParseCrtShResponse_IgnoresWildcard(t *testing.T) {
    jsonBody := `[{"common_name": "*.example.com", "name_value": "*.example.com"}]`
    subdomains, err := parseCrtShResponse(strings.NewReader(jsonBody), "example.com")
    if err != nil {
        t.Fatalf("parseCrtShResponse failed: %v", err)
    }
    if len(subdomains) != 0 {
        t.Fatalf("expected 0 subdomains, got %d", len(subdomains))
    }
}

func TestParseHackerTargetResponse_RespectsDomainSuffix(t *testing.T) {
    body := "api.example.com.evil,1.1.1.1\n"
    subdomains := parseHackerTargetResponse(strings.NewReader(body), "example.com")
    if len(subdomains) != 0 {
        t.Fatalf("expected 0 subdomains, got %d", len(subdomains))
    }
}

func TestParseDNSDumpsterResponse_RespectsDomainSuffix(t *testing.T) {
    html := `<td class="col-md-4">api.example.com.evil</td>`
    subdomains := parseDNSDumpsterResponse(strings.NewReader(html), "example.com")
    if len(subdomains) != 0 {
        t.Fatalf("expected 0 subdomains, got %d", len(subdomains))
    }
}

func TestWriteJSONOutput(t *testing.T) {
    buffer := &bytes.Buffer{}
    output := SubdomainOutput{Target: "example.com", Subdomains: []string{}, Count: 0, Timestamp: time.Now().UTC().Format(time.RFC3339)}
    if err := writeJSONOutput(buffer, output); err != nil {
        t.Fatalf("writeJSONOutput failed: %v", err)
    }
    if !json.Valid(buffer.Bytes()) {
        t.Fatal("expected valid JSON output")
    }
}

func TestProviderConfigDefaults(t *testing.T) {
    cfg := defaultProviderConfig()
    if cfg.CRTCrtShURL == "" || cfg.DNSDumpsterURL == "" || cfg.HackerTargetURL == "" {
        t.Fatal("expected default provider URLs to be set")
    }
}

func TestBuildOutput(t *testing.T) {
    output := buildOutput("example.com", []string{"a.example.com"})
    if output.Count != 1 || output.Target != "example.com" {
        t.Fatalf("unexpected output: %+v", output)
    }
    if output.Timestamp == "" {
        t.Fatal("expected timestamp set")
    }
}
