package main

import (
    "bytes"
    "context"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "sort"
    "strings"
    "sync"
    "time"
)

const (
    defaultTimeoutSeconds = 30
    userAgentString       = "Mozilla/5.0 (X-Caliber Recon)"
)

type SubdomainOutput struct {
    Target     string   `json:"target"`
    Subdomains []string `json:"subdomains"`
    Count      int      `json:"count"`
    Timestamp  string   `json:"timestamp"`
}

type ProviderConfig struct {
    CRTCrtShURL     string
    DNSDumpsterURL  string
    HackerTargetURL string
}

type providerResult struct {
    Subdomains []string
    Err        error
}

// EnumerateSubdomains returns a slice of discovered subdomains.
func EnumerateSubdomains() []string {
    return []string{}
}

func defaultProviderConfig() ProviderConfig {
    return ProviderConfig{
        CRTCrtShURL:     "https://crt.sh/?q=%.%s&output=json",
        DNSDumpsterURL:  "https://dnsdumpster.com/",
        HackerTargetURL: "https://api.hackertarget.com/hostsearch/?q=%s",
    }
}

// EnumerateSubdomains returns a slice of discovered subdomains.
func main() {
    var (
        target   string
        output   string
        timeout  int
        outputJS bool
    )

    flag.StringVar(&target, "target", "", "Target domain")
    flag.StringVar(&target, "t", "", "Target domain (alias for --target)")
    flag.StringVar(&output, "output", "", "Output file path (optional, defaults to stdout)")
    flag.StringVar(&output, "o", "", "Output file path (alias for --output)")
    flag.IntVar(&timeout, "timeout", defaultTimeoutSeconds, "Request timeout in seconds")
    flag.IntVar(&timeout, "T", defaultTimeoutSeconds, "Request timeout in seconds (alias for --timeout)")
    flag.BoolVar(&outputJS, "json", true, "Output JSON format (default: true)")

    flag.Parse()

    if target == "" {
        fmt.Fprintln(os.Stderr, "Error: --target is required")
        os.Exit(1)
    }

    normalized, ok := normalizeDomain(target)
    if !ok {
        fmt.Fprintln(os.Stderr, "Error: invalid target domain")
        os.Exit(1)
    }

    client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
    subdomains := enumerateSubdomains(normalized, client, defaultProviderConfig())
    outputData := buildOutput(normalized, subdomains)

    if !outputJS {
        for _, sub := range outputData.Subdomains {
            fmt.Fprintln(os.Stdout, sub)
        }
        return
    }

    if output != "" {
        file, err := os.Create(output)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
            os.Exit(1)
        }
        defer file.Close()
        if err := writeJSONOutput(file, outputData); err != nil {
            fmt.Fprintf(os.Stderr, "Error writing JSON output: %v\n", err)
            os.Exit(1)
        }
        return
    }

    if err := writeJSONOutput(os.Stdout, outputData); err != nil {
        fmt.Fprintf(os.Stderr, "Error writing JSON output: %v\n", err)
        os.Exit(1)
    }
}

func enumerateSubdomains(domain string, client *http.Client, cfg ProviderConfig) []string {
    if client == nil {
        return []string{}
    }
    normalized, ok := normalizeDomain(domain)
    if !ok {
        return []string{}
    }

    results := make(chan providerResult, 3)
    var wg sync.WaitGroup
    wg.Add(3)

    go func() {
        defer wg.Done()
        subdomains, err := queryCrtSh(normalized, client, cfg)
        results <- providerResult{Subdomains: subdomains, Err: providerError("crt.sh", err)}
    }()

    go func() {
        defer wg.Done()
        subdomains, err := queryDNSDumpster(normalized, client, cfg)
        results <- providerResult{Subdomains: subdomains, Err: providerError("dnsdumpster", err)}
    }()

    go func() {
        defer wg.Done()
        subdomains, err := queryHackerTarget(normalized, client, cfg)
        results <- providerResult{Subdomains: subdomains, Err: providerError("hackertarget", err)}
    }()

    wg.Wait()
    close(results)

    var aggregated []string
    for result := range results {
        if result.Err != nil {
            fmt.Fprintln(os.Stderr, result.Err.Error())
        }
        if len(result.Subdomains) > 0 {
            aggregated = append(aggregated, result.Subdomains...)
        }
    }

    return deduplicateAndNormalize(aggregated)
}

func queryCrtSh(domain string, client *http.Client, cfg ProviderConfig) ([]string, error) {
    if cfg.CRTCrtShURL == "" {
        return nil, errors.New("crt.sh url missing")
    }
    endpoint := fmt.Sprintf(cfg.CRTCrtShURL, domain)
    body, err := fetchProvider(endpoint, client)
    if err != nil {
        return nil, err
    }
    return parseCrtShResponse(bytes.NewReader(body), domain)
}

func queryDNSDumpster(domain string, client *http.Client, cfg ProviderConfig) ([]string, error) {
    if cfg.DNSDumpsterURL == "" {
        return nil, errors.New("dnsdumpster url missing")
    }
    // DNSDumpster passive DNS endpoint (HTML parsing). Source: https://dnsdumpster.com/
    body, err := fetchProvider(cfg.DNSDumpsterURL, client)
    if err != nil {
        return nil, err
    }
    return parseDNSDumpsterResponse(bytes.NewReader(body), domain), nil
}

func queryHackerTarget(domain string, client *http.Client, cfg ProviderConfig) ([]string, error) {
    if cfg.HackerTargetURL == "" {
        return nil, errors.New("hackertarget url missing")
    }
    endpoint := fmt.Sprintf(cfg.HackerTargetURL, domain)
    body, err := fetchProvider(endpoint, client)
    if err != nil {
        return nil, err
    }
    return parseHackerTargetResponse(bytes.NewReader(body), domain), nil
}

func fetchProvider(endpoint string, client *http.Client) ([]byte, error) {
    return fetchProviderWithContext(context.Background(), endpoint, client)
}

func fetchProviderWithContext(ctx context.Context, endpoint string, client *http.Client) ([]byte, error) {
    if client == nil {
        return nil, errors.New("http client is nil")
    }
    if endpoint == "" {
        return nil, errors.New("endpoint is empty")
    }

    requestContext := ctx
    if client.Timeout > 0 {
        var cancel context.CancelFunc
        requestContext, cancel = context.WithTimeout(ctx, client.Timeout)
        defer cancel()
    }

    req, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint, nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("User-Agent", userAgentString)

    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
    }
    return io.ReadAll(resp.Body)
}

func parseCrtShResponse(reader io.Reader, domain string) ([]string, error) {
    var entries []map[string]string
    decoder := json.NewDecoder(reader)
    if err := decoder.Decode(&entries); err != nil {
        return nil, err
    }

    var subdomains []string
    for _, entry := range entries {
        if nameValue, ok := entry["name_value"]; ok {
            for _, name := range strings.Split(nameValue, "\n") {
                cleaned := strings.TrimSpace(name)
                if cleaned == "" {
                    continue
                }
                subdomains = append(subdomains, cleaned)
            }
        }
        if commonName, ok := entry["common_name"]; ok {
            cleaned := strings.TrimSpace(commonName)
            if cleaned != "" {
                subdomains = append(subdomains, cleaned)
            }
        }
    }

    return filterByDomain(subdomains, domain), nil
}

func parseHackerTargetResponse(reader io.Reader, domain string) []string {
    body, err := io.ReadAll(reader)
    if err != nil {
        return []string{}
    }
    lines := strings.Split(string(body), "\n")
    var subdomains []string
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        parts := strings.Split(line, ",")
        if len(parts) < 1 {
            continue
        }
        host := strings.TrimSpace(parts[0])
        if host == "" {
            continue
        }
        subdomains = append(subdomains, host)
    }
    return filterByDomain(subdomains, domain)
}

func parseDNSDumpsterResponse(reader io.Reader, domain string) []string {
    body, err := io.ReadAll(reader)
    if err != nil {
        return []string{}
    }

    re := regexp.MustCompile(`(?i)\b([a-z0-9_-]+\.)+` + regexp.QuoteMeta(domain) + `\b`)
    matches := re.FindAllString(string(body), -1)
    if len(matches) == 0 {
        return []string{}
    }
    return filterByDomain(matches, domain)
}

func filterByDomain(subdomains []string, domain string) []string {
    var filtered []string
    domain = strings.ToLower(strings.TrimSpace(domain))
    for _, sub := range subdomains {
        cleaned := strings.TrimSpace(strings.ToLower(sub))
        if cleaned == "" {
            continue
        }
        if strings.HasPrefix(cleaned, "*.") {
            continue
        }
        if strings.Contains(cleaned, "@") {
            continue
        }
        if cleaned == domain {
            continue
        }
        if strings.HasSuffix(cleaned, "."+domain) {
            filtered = append(filtered, cleaned)
        }
    }
    return filtered
}

func deduplicateAndNormalize(subdomains []string) []string {
    seen := make(map[string]struct{})
    var unique []string
    for _, sub := range subdomains {
        cleaned := strings.ToLower(strings.TrimSpace(sub))
        if cleaned == "" {
            continue
        }
        if strings.Contains(cleaned, " ") {
            continue
        }
        if _, exists := seen[cleaned]; exists {
            continue
        }
        seen[cleaned] = struct{}{}
        unique = append(unique, cleaned)
    }
    sort.Strings(unique)
    return unique
}

func normalizeDomain(raw string) (string, bool) {
    trimmed := strings.TrimSpace(raw)
    if trimmed == "" {
        return "", false
    }

    if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
        parsed, err := url.Parse(trimmed)
        if err != nil || parsed.Host == "" {
            return "", false
        }
        trimmed = parsed.Host
    }

    trimmed = strings.ToLower(strings.TrimSpace(trimmed))
    if strings.Contains(trimmed, "/") {
        parts := strings.Split(trimmed, "/")
        trimmed = parts[0]
    }
    trimmed = strings.Trim(trimmed, ".")

    if !isValidDomain(trimmed) {
        return "", false
    }

    parts := strings.Split(trimmed, ".")
    if len(parts) < 2 {
        return "", false
    }
    base := strings.Join(parts[len(parts)-2:], ".")
    if !isValidDomain(base) {
        return "", false
    }
    return base, true
}

func isValidDomain(domain string) bool {
    if domain == "" || strings.Contains(domain, " ") {
        return false
    }
    domain = strings.Trim(domain, ".")
    parts := strings.Split(domain, ".")
    if len(parts) < 2 {
        return false
    }
    for _, part := range parts {
        if part == "" || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
            return false
        }
    }
    return true
}

func providerError(provider string, err error) error {
    if err == nil {
        return nil
    }
    return fmt.Errorf("%s: %w", provider, err)
}

func buildOutput(target string, subdomains []string) SubdomainOutput {
    return SubdomainOutput{
        Target:     target,
        Subdomains: subdomains,
        Count:      len(subdomains),
        Timestamp:  time.Now().UTC().Format(time.RFC3339),
    }
}

func writeJSONOutput(writer io.Writer, output SubdomainOutput) error {
    if writer == nil {
        return errors.New("writer is nil")
    }
    encoder := json.NewEncoder(writer)
    encoder.SetIndent("", "  ")
    return encoder.Encode(output)
}
