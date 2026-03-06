package main

import (
    "bufio"
    "bytes"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
    "time"

    "golang.org/x/net/html"
)

const (
    defaultTimeout  = 10 * time.Second
    defaultWorkers  = 50
    maxBodyBytes    = 1 << 20
    maxRedirects    = 3
    userAgentString = "Mozilla/5.0 (X-Caliber Recon)"
)

type ProbeResult struct {
    URL           string  `json:"url"`
    StatusCode    int     `json:"status_code"`
    ResponseTime  float64 `json:"response_time"`
    Title         string  `json:"title,omitempty"`
    ContentLength int64   `json:"content_length,omitempty"`
    Error         string  `json:"error,omitempty"`
    Technologies  []string `json:"technologies,omitempty"`
}

type ProbeOutput struct {
    URLs      []string      `json:"urls"`
    Results   []ProbeResult `json:"results"`
    Timestamp string        `json:"timestamp"`
}

func main() {
    urlsFile := flag.String("urls", "", "path to newline-delimited URLs")
    workers := flag.Int("workers", defaultWorkers, "max concurrent probes")
    timeout := flag.Duration("timeout", defaultTimeout, "per-request timeout")
    flag.Parse()

    urls := collectURLs(*urlsFile, flag.Args())
    if len(urls) == 0 {
        return
    }

    results := probeURLs(urls, *workers, *timeout)
    output := ProbeOutput{
        URLs:      urls,
        Results:   results,
        Timestamp: time.Now().UTC().Format(time.RFC3339),
    }

    encoder := json.NewEncoder(os.Stdout)
    if err := encoder.Encode(output); err != nil {
        fmt.Fprintln(os.Stderr, "failed to write JSON output:", err)
    }
}

func collectURLs(filePath string, args []string) []string {
    var urls []string

    if filePath != "" {
        fileURLs, err := readURLsFromFile(filePath)
        if err != nil {
            fmt.Fprintln(os.Stderr, "failed to read urls file:", err)
        } else {
            urls = append(urls, fileURLs...)
        }
    }

    if len(args) > 0 {
        urls = append(urls, args...)
    }

    stdinURLs, err := readURLsFromReader(os.Stdin)
    if err == nil {
        urls = append(urls, stdinURLs...)
    }

    return filterValidURLs(urls)
}

func readURLsFromFile(path string) ([]string, error) {
    file, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer file.Close()
    return readURLsFromReader(file)
}

func readURLsFromReader(reader io.Reader) ([]string, error) {
    if reader == os.Stdin {
        info, err := os.Stdin.Stat()
        if err == nil && info.Mode()&os.ModeCharDevice != 0 {
            return nil, nil
        }
    }

    scanner := bufio.NewScanner(reader)
    var urls []string
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" {
            continue
        }
        urls = append(urls, line)
    }
    if err := scanner.Err(); err != nil {
        return nil, err
    }
    return urls, nil
}

func filterValidURLs(urls []string) []string {
    var valid []string
    seen := make(map[string]struct{})
    for _, raw := range urls {
        trimmed := strings.TrimSpace(raw)
        if trimmed == "" {
            continue
        }
        normalized, ok := normalizeURL(trimmed)
        if !ok {
            fmt.Fprintln(os.Stderr, "invalid url:", trimmed)
            continue
        }
        if _, exists := seen[normalized]; exists {
            continue
        }
        seen[normalized] = struct{}{}
        valid = append(valid, normalized)
    }
    return valid
}

func normalizeURL(raw string) (string, bool) {
    parsed, err := url.Parse(raw)
    if err == nil && parsed.Scheme != "" && parsed.Host != "" {
        return parsed.String(), true
    }
    if err == nil && parsed.Scheme == "" && parsed.Host != "" {
        return "https://" + parsed.Host, true
    }
    if err == nil && parsed.Scheme == "" && parsed.Host == "" && parsed.Path != "" {
        host := strings.TrimSpace(parsed.Path)
        if host == "" {
            return "", false
        }
        return "https://" + host, true
    }
    return "", false
}

func probeURLs(urls []string, workers int, timeout time.Duration) []ProbeResult {
    if workers <= 0 {
        workers = defaultWorkers
    }
    if workers > defaultWorkers {
        workers = defaultWorkers
    }

    jobs := make(chan string, len(urls))
    results := make(chan ProbeResult, len(urls))

    var wg sync.WaitGroup
    for i := 0; i < workers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for target := range jobs {
                results <- probeURL(target, timeout)
            }
        }()
    }

    for _, target := range urls {
        jobs <- target
    }
    close(jobs)

    wg.Wait()
    close(results)

    probeResults := make([]ProbeResult, 0, len(urls))
    for result := range results {
        probeResults = append(probeResults, result)
    }
    return probeResults
}

func probeURL(target string, timeout time.Duration) ProbeResult {
    if target == "" {
        return ProbeResult{URL: target, StatusCode: 0, Error: "empty url"}
    }

    if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
        return probeWithScheme(target, timeout)
    }

    httpsResult := probeWithScheme("https://"+target, timeout)
    if httpsResult.StatusCode != 0 || httpsResult.Error == "" {
        return httpsResult
    }

    httpResult := probeWithScheme("http://"+target, timeout)
    if httpsResult.Error != "" {
        httpResult.Error = fmt.Sprintf("https error: %s; http error: %s", httpsResult.Error, httpResult.Error)
    }
    return httpResult
}

func probeWithScheme(target string, timeout time.Duration) ProbeResult {
    start := time.Now()
    client := &http.Client{
        Timeout: timeout,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if len(via) >= maxRedirects {
                return http.ErrUseLastResponse
            }
            return nil
        },
    }

    req, err := http.NewRequest(http.MethodGet, target, nil)
    if err != nil {
        return ProbeResult{URL: target, StatusCode: 0, Error: err.Error()}
    }
    req.Header.Set("User-Agent", userAgentString)

    resp, err := client.Do(req)
    if err != nil {
        return ProbeResult{URL: target, StatusCode: 0, Error: err.Error()}
    }
    defer resp.Body.Close()

    if resp.Request != nil && resp.Request.URL != nil {
        target = resp.Request.URL.String()
    }

    limited := io.LimitReader(resp.Body, maxBodyBytes)
    bodyBytes, readErr := io.ReadAll(limited)
    if readErr != nil && !errors.Is(readErr, io.EOF) {
        return ProbeResult{URL: target, StatusCode: resp.StatusCode, ResponseTime: time.Since(start).Seconds(), Error: readErr.Error()}
    }

    title := extractTitle(bytes.NewReader(bodyBytes))
    responseTime := time.Since(start).Seconds()
    contentLength := resp.ContentLength
    if contentLength < 0 {
        contentLength = int64(len(bodyBytes))
    }

    technologies := detectTechnologies(resp.Header, bodyBytes)

    return ProbeResult{
        URL:           target,
        StatusCode:    resp.StatusCode,
        ResponseTime:  responseTime,
        Title:         title,
        ContentLength: contentLength,
        Technologies:  technologies,
    }
}

func extractTitle(body io.Reader) string {
    doc, err := html.Parse(body)
    if err != nil {
        return ""
    }

    var title string
    var findTitle func(*html.Node)
    findTitle = func(n *html.Node) {
        if n.Type == html.ElementNode && n.Data == "title" {
            if n.FirstChild != nil {
                title = n.FirstChild.Data
            }
        }
        for c := n.FirstChild; c != nil; c = c.NextSibling {
            findTitle(c)
        }
    }
    findTitle(doc)
    return title
}

func detectTechnologies(headers http.Header, body []byte) []string {
    techSet := make(map[string]struct{})

    addHeader := func(key string) {
        value := strings.TrimSpace(headers.Get(key))
        if value != "" {
            techSet[fmt.Sprintf("%s: %s", strings.ToLower(key), value)] = struct{}{}
        }
    }

    addHeader("Server")
    addHeader("X-Powered-By")
    addHeader("Via")
    addHeader("X-AspNet-Version")

    doc, err := html.Parse(bytes.NewReader(body))
    if err == nil {
        var walk func(*html.Node)
        walk = func(n *html.Node) {
            if n.Type == html.ElementNode && n.Data == "meta" {
                var name, content string
                for _, attr := range n.Attr {
                    if strings.EqualFold(attr.Key, "name") {
                        name = attr.Val
                    }
                    if strings.EqualFold(attr.Key, "content") {
                        content = attr.Val
                    }
                }
                if strings.EqualFold(name, "generator") && content != "" {
                    techSet[fmt.Sprintf("generator: %s", content)] = struct{}{}
                }
            }
            for c := n.FirstChild; c != nil; c = c.NextSibling {
                walk(c)
            }
        }
        walk(doc)
    }

    if len(techSet) == 0 {
        return nil
    }
    technologies := make([]string, 0, len(techSet))
    for tech := range techSet {
        technologies = append(technologies, tech)
    }
    return technologies
}
