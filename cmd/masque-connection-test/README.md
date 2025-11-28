# MASQUE Connection Test Suite

Comprehensive testing tool for validating MASQUE connections with multiple test scenarios.

## 🚀 Quick Start

### Build

```bash
# Windows
cd d:\Projects\github\vwarp
go build -o masque-connection-test.exe .\cmd\masque-connection-test\main.go

# Linux/macOS
cd vwarp
go build -o masque-connection-test ./cmd/masque-connection-test/main.go
```

### Run All Tests

```bash
.\masque-connection-test.exe
```

## 📋 Test Types

### 1. Basic Connection Test
Verifies that the MASQUE client is connected and has valid IP addresses assigned.

```bash
.\masque-connection-test.exe -test connection
```

### 2. DNS Resolution Test
Tests DNS queries through the MASQUE tunnel.

```bash
.\masque-connection-test.exe -test dns
```

### 3. HTTP Connection Test
Tests HTTP connectivity through the tunnel.

```bash
.\masque-connection-test.exe -test http
```

### 4. HTTPS Connection Test
Tests HTTPS connectivity with TLS validation.

```bash
.\masque-connection-test.exe -test https
```

### 5. Speed Test
Measures download speed through the tunnel.

```bash
.\masque-connection-test.exe -test speed -duration 30s
```

### 6. Latency Test
Measures round-trip latency with multiple ping samples.

```bash
.\masque-connection-test.exe -test latency
```

### 7. Stability Test
Tests connection stability over time with continuous requests.

```bash
.\masque-connection-test.exe -test stability -duration 60s
```

## 🎯 Usage Examples

### Run All Tests with Verbose Output

```bash
.\masque-connection-test.exe -test all -v
```

### Run Speed Test for 60 seconds

```bash
.\masque-connection-test.exe -test speed -duration 60s
```

### Output Results as JSON

```bash
.\masque-connection-test.exe -test all -json > results.json
```

### Continuous Monitoring

Run tests continuously every 5 minutes:

```bash
.\masque-connection-test.exe -continuous -interval 5m -test all
```

### Use Custom Config File

```bash
.\masque-connection-test.exe -config "C:\custom\path\masque_config.json"
```

## 🔧 Command Line Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-config` | string | platform-specific | Path to MASQUE config file |
| `-test` | string | `all` | Test to run: all, connection, dns, http, https, speed, latency, stability |
| `-v` | bool | `false` | Enable verbose logging |
| `-duration` | duration | `30s` | Duration for speed/stability tests |
| `-json` | bool | `false` | Output results as JSON |
| `-continuous` | bool | `false` | Run tests continuously |
| `-interval` | duration | `60s` | Interval between continuous test runs |

## 📊 Test Results

### Console Output

```
═══════════════════════════════════════════════════════════
📊 TEST RESULTS SUMMARY
═══════════════════════════════════════════════════════════

✅ Basic Connection: PASSED (123ms)
   IPv4: 172.16.0.2, IPv6: 2606:4700:110:87df:1f60:fdd5:7f96:86e2

✅ DNS Resolution: PASSED (456ms)
   Resolved 6 addresses: [142.250.185.46 ...]

✅ HTTP Connection: PASSED (789ms)
   Status: 200 OK

✅ HTTPS Connection: PASSED (891ms)
   Status: 200 OK, TLS: 771

✅ Latency Test: PASSED (2.1s)
   Min: 45ms, Avg: 67ms, Max: 102ms (10/10 successful)

✅ Speed Test: PASSED (30.5s)
   Downloaded 45.2 MB in 30s (12.1 Mbps)

✅ Stability Test: PASSED (60.2s)
   Success: 59/60 (98.3%), Failed: 1

═══════════════════════════════════════════════════════════
📈 Total: 7 tests | ✅ Passed: 7 | ❌ Failed: 0
⏱️  Total Duration: 95.067s
🎉 All tests passed!
═══════════════════════════════════════════════════════════
```

### JSON Output

```json
{
  "timestamp": "2025-11-27T12:00:00Z",
  "total": 7,
  "passed": 7,
  "failed": 0,
  "results": [
    {
      "name": "Basic Connection",
      "success": true,
      "duration": 123000000,
      "details": "IPv4: 172.16.0.2, IPv6: 2606:4700:110:87df:1f60:fdd5:7f96:86e2",
      "timestamp": "2025-11-27T12:00:00Z"
    }
  ]
}
```

## 🎨 Test Scenarios

### Quick Health Check

```bash
.\masque-connection-test.exe -test connection -test dns -test http
```

### Performance Benchmark

```bash
.\masque-connection-test.exe -test speed -test latency -duration 120s -v
```

### Long-term Stability Monitoring

```bash
.\masque-connection-test.exe -continuous -interval 10m -test stability -duration 120s
```

### Integration with CI/CD

```bash
# Exit code 0 if all tests pass, 1 if any fail
.\masque-connection-test.exe -json | jq '.failed == 0'
```

## 🐛 Troubleshooting

### Config Not Found

```bash
# First register to create config
.\masque-register.exe

# Then run tests
.\masque-connection-test.exe
```

### Connection Timeout

```bash
# Run with verbose logging to see details
.\masque-connection-test.exe -v -test connection
```

### DNS Resolution Fails

This indicates the tunnel is up but DNS traffic isn't routing correctly. Check:
- System DNS settings
- VPN/TUN adapter configuration
- Firewall rules

### Speed Test Slow

Try different test durations to get more accurate measurements:

```bash
.\masque-connection-test.exe -test speed -duration 120s
```

## 📈 Monitoring Script

Create a PowerShell script for continuous monitoring:

```powershell
# monitor.ps1
while ($true) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "`n[$timestamp] Running MASQUE tests..."
    
    .\masque-connection-test.exe -test all -json | `
        Tee-Object -FilePath "logs\masque-test-$((Get-Date).ToString('yyyyMMdd')).json" -Append
    
    Start-Sleep -Seconds 300  # 5 minutes
}
```

Run it:

```bash
mkdir logs
powershell -File monitor.ps1
```

## 🔍 Advanced Usage

### Custom Test Workflow

```bash
# 1. Quick connection check
.\masque-connection-test.exe -test connection -v

# 2. If connected, run full suite
if ($LASTEXITCODE -eq 0) {
    .\masque-connection-test.exe -test all -duration 60s -json > results.json
}

# 3. Parse results
Get-Content results.json | ConvertFrom-Json | Select-Object -ExpandProperty results
```

### Automated Alerting

```powershell
# test-and-alert.ps1
$result = .\masque-connection-test.exe -test all -json | ConvertFrom-Json

if ($result.failed -gt 0) {
    # Send alert (email, webhook, etc.)
    Write-Host "❌ Tests failed! Failed count: $($result.failed)"
    exit 1
} else {
    Write-Host "✅ All tests passed!"
    exit 0
}
```

## 📝 Notes

- **Speed tests** download from Cloudflare's speed test endpoint
- **Latency tests** ping Cloudflare DNS (1.1.1.1)
- **Stability tests** use Firefox's captive portal detection endpoint
- All HTTP tests use Go's standard HTTP client with no tunnel-specific configuration
- Tests verify end-to-end connectivity, not just MASQUE tunnel status

## 🤝 Integration Examples

### Python Integration

```python
import subprocess
import json

result = subprocess.run(
    ['masque-connection-test.exe', '-test', 'all', '-json'],
    capture_output=True,
    text=True
)

data = json.loads(result.stdout)
print(f"Tests: {data['total']}, Passed: {data['passed']}, Failed: {data['failed']}")
```

### Bash Integration

```bash
#!/bin/bash
./masque-connection-test -test all -json | jq -r '.results[] | "\(.name): \(if .success then "✅" else "❌" end)"'
```

## 📦 Building for Multiple Platforms

```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o masque-connection-test-windows.exe

# Linux
GOOS=linux GOARCH=amd64 go build -o masque-connection-test-linux

# macOS
GOOS=darwin GOARCH=amd64 go build -o masque-connection-test-macos

# ARM (Raspberry Pi, Android)
GOOS=linux GOARCH=arm64 go build -o masque-connection-test-arm64
```

## 🎯 Use Cases

1. **Development**: Verify MASQUE implementation works correctly
2. **CI/CD**: Automated testing in deployment pipelines
3. **Monitoring**: Continuous health checks of MASQUE service
4. **Debugging**: Detailed diagnostics when connection issues occur
5. **Performance**: Benchmark different endpoints and configurations
6. **Documentation**: Generate reports for connection quality

## 🔗 Related Tools

- `masque-register.exe` - Register and create MASQUE config
- `masque-test.exe` - Interactive MASQUE client with scanner
- `masque-proxy.exe` - SOCKS5 proxy over MASQUE

## 📄 License

Same license as the vwarp project.
