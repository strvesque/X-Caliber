# Port Scanner (Go)

High-performance TCP port scanner with concurrent scanning, service detection, and JSON output.

## Features

- **TCP Connect Scan**: Portable scanning without requiring root privileges
- **Concurrent Scanning**: Worker pool pattern with configurable concurrency (default: 100 workers)
- **Service Detection**: 200+ common service mappings (HTTP, SSH, MySQL, Redis, etc.)
- **Flexible Port Specification**: 
  - Single port: `80`
  - Range: `1-1000`
  - List: `22,80,443`
  - Combined: `1-10,20,30-40`
  - Top N common ports: `--top-ports 100`
- **JSON Output**: Matches IPC schema for integration with Python orchestrator
- **Configurable Timeouts**: Per-port timeout (default: 1000ms)
- **Rate Limiting**: Worker pool prevents network flooding

## Installation

```bash
cd recon_go/portscan
go build -o xcal-portscan
```

## Usage

### Basic Usage

```bash
# Scan localhost ports 1-1000
./xcal-portscan 127.0.0.1 -p 1-1000

# Scan specific ports
./xcal-portscan example.com --ports 22,80,443

# Scan top 100 common ports (default if no -p specified)
./xcal-portscan 192.168.1.1

# Scan top 1000 ports
./xcal-portscan 10.0.0.1 --top-ports 1000
```

### Advanced Options

```bash
# Custom concurrency (200 workers)
./xcal-portscan 192.168.1.0 -p 1-65535 -c 200

# Custom timeout (500ms per port)
./xcal-portscan 192.168.1.1 -p 1-1000 -t 500

# Combine options
./xcal-portscan example.com -p 1-10000 -c 150 -t 800
```

### CLI Options

```
-p, --ports string        Port specification (e.g., '80', '1-100', '22,80,443')
--top-ports int          Scan top N common ports (e.g., 100)
-c, --concurrency int    Max concurrent workers (default: 100)
-t, --timeout int        Timeout per port in milliseconds (default: 1000)
--json                   Output JSON format (default: true)
```

## Output Format

### JSON Output (Default)

Matches IPC schema for orchestrator integration:

```json
{
  "target": "192.168.1.1",
  "open_ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "service": "ssh"
    },
    {
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "service": "http"
    },
    {
      "port": 443,
      "protocol": "tcp",
      "state": "open",
      "service": "https"
    }
  ],
  "scan_time": 2.5,
  "timestamp": "2026-03-06T12:34:56Z"
}
```

### Human-Readable Output

```bash
./xcal-portscan 127.0.0.1 -p 1-100 --json=false
```

Output:
```
Scan Results for 127.0.0.1
Scanned 100 ports in 0.52 seconds
Found 2 open ports:

  22/tcp    open    ssh
  80/tcp    open    http
```

## Performance

- **1000 ports**: < 5 seconds (with 100 workers, 1s timeout)
- **10,000 ports**: < 30 seconds (with 200 workers, 500ms timeout)
- **Concurrency limit**: Safety capped at 500 workers to prevent resource exhaustion

## Service Detection

The scanner includes a database of 200+ common services:

| Port | Service | Category |
|------|---------|----------|
| 22 | ssh | Remote Access |
| 80 | http | Web |
| 443 | https | Web |
| 3306 | mysql | Database |
| 5432 | postgresql | Database |
| 6379 | redis | Database |
| 8080 | http-proxy | Web |
| 27017 | mongodb | Database |

See `services.go` for the complete list.

## Testing

```bash
# Run all tests
go test ./portscan -v

# Run with coverage
go test ./portscan -v -cover

# Run specific test
go test ./portscan -v -run TestScanPort
```

**Test Coverage**: 70%+ target

## Architecture

### Core Components

1. **scanPort()**: TCP connect scan for single port
   - Uses `net.DialTimeout()` for connection attempts
   - Returns `PortResult` with state (open/closed/filtered)
   - Detects service via port mapping

2. **scanPorts()**: Concurrent scan orchestrator
   - Worker pool pattern with goroutines
   - Job queue (buffered channel) for port distribution
   - Result collection channel
   - Returns only open ports

3. **detectService()**: Service identification
   - 200+ port-to-service mappings
   - Returns "unknown" for unmapped ports
   - Extensible via `commonServices` map

4. **parsePortRange()**: Port specification parser
   - Supports single, range, list, and combined formats
   - Deduplicates ports
   - Validates port ranges (1-65535)

### Concurrency Model

```
              Jobs Channel
                   ↓
    ┌──────────────┼──────────────┐
    │              │              │
 Worker 1      Worker 2      Worker N
    │              │              │
    └──────────────┼──────────────┘
                   ↓
             Results Channel
                   ↓
          Filter Open Ports
                   ↓
            JSON Output
```

**Benefits**:
- Fixed worker pool prevents resource exhaustion
- Buffered channels minimize blocking
- WaitGroup ensures all scans complete
- Results collected asynchronously

## Integration with Python Orchestrator

The scanner outputs JSON matching the `port_scan` schema in `schemas/ipc_protocol.json`:

```python
import subprocess
import json

# Run scanner
result = subprocess.run(
    ['./xcal-portscan', '192.168.1.1', '-p', '1-1000'],
    capture_output=True,
    text=True
)

# Parse JSON output
scan_data = json.loads(result.stdout)
print(f"Found {len(scan_data['open_ports'])} open ports")
```

## Error Handling

- **Invalid target**: Exits with error message
- **Network unreachable**: Returns empty `open_ports` array
- **Timeout**: Port marked as "filtered", scan continues
- **Invalid port spec**: Parser error with helpful message

## Security Considerations

1. **No raw sockets**: Uses TCP connect scan (no root required)
2. **Rate limiting**: Worker pool prevents network flooding
3. **Timeout enforcement**: Prevents hanging on slow/dead hosts
4. **Input validation**: Port ranges validated (1-65535)

## Limitations

- **No SYN scan**: Requires raw sockets (root), not portable
- **TCP only**: No UDP scanning support
- **No OS detection**: Basic service detection only
- **No version detection**: Port mapping based, no banner analysis

## Future Enhancements

1. **Banner grabbing**: Read service banners for version detection
2. **UDP support**: Add UDP port scanning
3. **OS fingerprinting**: TCP/IP stack fingerprinting
4. **Parallel host scanning**: Scan multiple targets concurrently
5. **Output formats**: XML, CSV support

## References

- IPC Schema: `../../schemas/ipc_protocol.json`
- Go net package: https://pkg.go.dev/net
- Worker pool pattern: https://gobyexample.com/worker-pools

## License

Part of X-Caliber automation extension.
