package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PortResult represents a single port scan result
type PortResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
}

// ScanResult represents the complete scan output matching IPC schema
type ScanResult struct {
	Target    string       `json:"target"`
	OpenPorts []PortResult `json:"open_ports"`
	ScanTime  float64      `json:"scan_time"`
	Timestamp string       `json:"timestamp"`
}

// scanPort performs TCP connect scan on a single port
func scanPort(target string, port int, timeout time.Duration) PortResult {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, timeout)

	result := PortResult{
		Port:     port,
		Protocol: "tcp",
		State:    "closed",
		Service:  "",
	}

	if err != nil {
		// Connection failed - port is closed or filtered
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.State = "filtered"
		}
		return result
	}

	// Connection successful - port is open
	defer conn.Close()
	result.State = "open"
	result.Service = detectService(port)

	return result
}

// scanPorts scans multiple ports concurrently using worker pool pattern
func scanPorts(target string, ports []int, workers int, timeout time.Duration) []PortResult {
	if workers <= 0 {
		workers = 100 // Default concurrency
	}
	if workers > 500 {
		workers = 500 // Safety limit
	}

	jobs := make(chan int, len(ports))
	results := make(chan PortResult, len(ports))

	// Start worker pool
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				results <- scanPort(target, port, timeout)
			}
		}()
	}

	// Send jobs to workers
	for _, port := range ports {
		jobs <- port
	}
	close(jobs)

	// Wait for all workers to complete
	wg.Wait()
	close(results)

	// Collect only open ports
	var openPorts []PortResult
	for r := range results {
		if r.State == "open" {
			openPorts = append(openPorts, r)
		}
	}

	return openPorts
}

// parsePortRange parses port specification string
// Supports: "80", "1-100", "22,80,443", "1-10,20,30-40"
func parsePortRange(portSpec string) ([]int, error) {
	if portSpec == "" {
		return nil, fmt.Errorf("empty port specification")
	}

	var ports []int
	seen := make(map[int]bool)

	parts := strings.Split(portSpec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)

		// Check for range notation (e.g., "1-100")
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range format: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", rangeParts[1])
			}

			if start > end {
				return nil, fmt.Errorf("invalid range: start (%d) > end (%d)", start, end)
			}
			if start < 1 || end > 65535 {
				return nil, fmt.Errorf("port range must be 1-65535")
			}

			for p := start; p <= end; p++ {
				if !seen[p] {
					ports = append(ports, p)
					seen[p] = true
				}
			}
		} else {
			// Single port
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port must be 1-65535: %d", port)
			}

			if !seen[port] {
				ports = append(ports, port)
				seen[port] = true
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports specified")
	}

	return ports, nil
}

// getTopPorts returns the top N most common ports
func getTopPorts(count int) []int {
	// Top 1000 most common ports (nmap default)
	commonPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
		143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
		20, 69, 137, 138, 161, 162, 389, 636, 1433, 1521,
		2049, 3690, 5432, 5800, 5900, 6379, 8000, 8443, 8888, 9090,
		// Extended list
		26, 37, 42, 43, 49, 79, 81, 88, 106, 109,
		113, 119, 123, 135, 156, 179, 194, 389, 427, 443,
		444, 445, 464, 465, 497, 512, 513, 514, 515, 543,
		544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
		1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755,
		1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389,
		3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432,
		5631, 5666, 5800, 5900, 6000, 6001, 6379, 6646, 7070, 8000,
		8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 27017,
	}

	if count <= 0 {
		return []int{}
	}
	if count > len(commonPorts) {
		count = len(commonPorts)
	}

	return commonPorts[:count]
}

// ScanPorts is the legacy exported function for backward compatibility
func ScanPorts() []int {
	return []int{}
}

func main() {
	// CLI flags
	var (
		portSpec   string
		topPorts   int
		workers    int
		timeout    int
		outputJSON bool
	)

	flag.StringVar(&portSpec, "p", "", "Port specification (e.g., '80', '1-100', '22,80,443')")
	flag.StringVar(&portSpec, "ports", "", "Port specification (alias for -p)")
	flag.IntVar(&topPorts, "top-ports", 0, "Scan top N common ports (e.g., 100)")
	flag.IntVar(&workers, "c", 100, "Max concurrent workers (default: 100)")
	flag.IntVar(&workers, "concurrency", 100, "Max concurrent workers (alias for -c)")
	flag.IntVar(&timeout, "t", 1000, "Timeout per port in milliseconds (default: 1000)")
	flag.IntVar(&timeout, "timeout", 1000, "Timeout per port in milliseconds (alias for -t)")
	flag.BoolVar(&outputJSON, "json", true, "Output JSON format (default: true)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] TARGET\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "High-performance TCP port scanner with concurrent scanning.\n\n")
		fmt.Fprintf(os.Stderr, "Arguments:\n")
		fmt.Fprintf(os.Stderr, "  TARGET                 Target IP address or domain name\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s 192.168.1.1 -p 1-1000\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s example.com --ports 22,80,443\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s 10.0.0.1 --top-ports 100\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s 127.0.0.1 -p 1-65535 -c 200 -t 500\n", os.Args[0])
	}

	flag.Parse()

	// Get target from positional argument
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Error: TARGET is required\n\n")
		flag.Usage()
		os.Exit(1)
	}
	target := args[0]

	// Determine which ports to scan
	var ports []int
	var err error

	if topPorts > 0 {
		ports = getTopPorts(topPorts)
	} else if portSpec != "" {
		ports, err = parsePortRange(portSpec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing port specification: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Default: scan top 100 common ports
		ports = getTopPorts(100)
	}

	if len(ports) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no ports to scan\n")
		os.Exit(1)
	}

	// Perform scan
	startTime := time.Now()
	openPorts := scanPorts(target, ports, workers, time.Duration(timeout)*time.Millisecond)
	scanDuration := time.Since(startTime).Seconds()

	// Build result
	result := ScanResult{
		Target:    target,
		OpenPorts: openPorts,
		ScanTime:  scanDuration,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Output results
	if outputJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Human-readable output
		fmt.Printf("Scan Results for %s\n", target)
		fmt.Printf("Scanned %d ports in %.2f seconds\n", len(ports), scanDuration)
		fmt.Printf("Found %d open ports:\n\n", len(openPorts))
		for _, p := range openPorts {
			fmt.Printf("  %d/tcp\t%s\t%s\n", p.Port, p.State, p.Service)
		}
	}
}
