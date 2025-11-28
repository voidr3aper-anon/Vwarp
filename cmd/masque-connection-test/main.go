package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/bepass-org/vwarp/masque"
	"github.com/bepass-org/vwarp/masque/usque/config"
)

// TestResult stores the result of a single test
type TestResult struct {
	Name      string        `json:"name"`
	Success   bool          `json:"success"`
	Duration  time.Duration `json:"duration"`
	Error     string        `json:"error,omitempty"`
	Details   string        `json:"details,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// TestSuite manages all test execution
type TestSuite struct {
	client  *masque.MasqueClient
	config  *config.Config
	results []TestResult
	mu      sync.Mutex
	logger  *slog.Logger
	verbose bool
}

func main() {
	// Flags
	configPath := flag.String("config", "", "Path to config file (default: platform-specific)")
	testName := flag.String("test", "all", "Test to run: all, connection, dns, http, https, speed, latency, stability")
	verbose := flag.Bool("v", false, "Verbose logging")
	duration := flag.Duration("duration", 30*time.Second, "Duration for stability/speed tests")
	jsonOutput := flag.Bool("json", false, "Output results as JSON")
	continuous := flag.Bool("continuous", false, "Run tests continuously")
	interval := flag.Duration("interval", 60*time.Second, "Interval between continuous test runs")

	flag.Parse()

	// Use platform-specific default config path if not specified
	if *configPath == "" {
		*configPath = masque.GetDefaultConfigPath()
	}

	// Setup logger
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Print banner
	if !*jsonOutput {
		printBanner()
	}

	// Load config
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load config from %s: %v\n", *configPath, err)
	}

	if !*jsonOutput {
		fmt.Printf("📁 Config: %s\n", *configPath)
		fmt.Printf("🆔 Device: %s\n", cfg.ID)
		fmt.Printf("📍 IPv4: %s | IPv6: %s\n\n", cfg.IPv4, cfg.IPv6)
	}

	// Run tests
	if *continuous {
		runContinuousTests(cfg, *configPath, *testName, *duration, *jsonOutput, *interval, logger, *verbose)
	} else {
		runTests(cfg, *configPath, *testName, *duration, *jsonOutput, logger, *verbose)
	}
}

func runContinuousTests(cfg *config.Config, configPath, testName string, duration time.Duration, jsonOutput bool, interval time.Duration, logger *slog.Logger, verbose bool) {
	iteration := 1
	for {
		if !jsonOutput {
			fmt.Printf("\n═══════════════════════════════════════════════════════════\n")
			fmt.Printf("🔄 Iteration %d - %s\n", iteration, time.Now().Format(time.RFC3339))
			fmt.Printf("═══════════════════════════════════════════════════════════\n\n")
		}

		runTests(cfg, configPath, testName, duration, jsonOutput, logger, verbose)

		if !jsonOutput {
			fmt.Printf("\n⏳ Waiting %v before next test run...\n", interval)
		}
		time.Sleep(interval)
		iteration++
	}
}

func runTests(cfg *config.Config, configPath, testName string, duration time.Duration, jsonOutput bool, logger *slog.Logger, verbose bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create MASQUE client
	client, err := masque.NewMasqueClient(ctx, masque.MasqueClientConfig{
		ConfigPath: configPath,
		Logger:     logger,
	})
	if err != nil {
		log.Fatalf("❌ Failed to create MASQUE client: %v", err)
	}
	defer client.Close()

	// Create test suite
	suite := &TestSuite{
		client:  client,
		config:  cfg,
		results: make([]TestResult, 0),
		logger:  logger,
		verbose: verbose,
	}

	// Run requested tests
	switch testName {
	case "all":
		suite.runAllTests(duration)
	case "connection":
		suite.testBasicConnection()
	case "dns":
		suite.testDNSResolution()
	case "http":
		suite.testHTTPConnection()
	case "https":
		suite.testHTTPSConnection()
	case "speed":
		suite.testSpeed(duration)
	case "latency":
		suite.testLatency()
	case "stability":
		suite.testStability(duration)
	default:
		log.Fatalf("Unknown test: %s", testName)
	}

	// Output results
	if jsonOutput {
		suite.outputJSON()
	} else {
		suite.outputSummary()
	}
}

func (ts *TestSuite) runAllTests(duration time.Duration) {
	tests := []struct {
		name string
		fn   func()
	}{
		{"Basic Connection", ts.testBasicConnection},
		{"DNS Resolution", ts.testDNSResolution},
		{"HTTP Connection", ts.testHTTPConnection},
		{"HTTPS Connection", ts.testHTTPSConnection},
		{"Latency Test", ts.testLatency},
	}

	for _, test := range tests {
		if !ts.verbose {
			fmt.Printf("⏳ Running: %s...\n", test.name)
		}
		test.fn()
	}

	// Run longer tests if duration allows
	if duration > 10*time.Second {
		if !ts.verbose {
			fmt.Printf("⏳ Running: Speed Test (%v)...\n", duration)
		}
		ts.testSpeed(duration)

		if !ts.verbose {
			fmt.Printf("⏳ Running: Stability Test (%v)...\n", duration)
		}
		ts.testStability(duration)
	}
}

func (ts *TestSuite) testBasicConnection() {
	start := time.Now()
	result := TestResult{
		Name:      "Basic Connection",
		Timestamp: start,
	}

	// Check if client is connected
	ipv4, ipv6 := ts.client.GetLocalAddresses()
	if ipv4 == "" && ipv6 == "" {
		result.Success = false
		result.Error = "No IP addresses assigned"
	} else {
		result.Success = true
		result.Details = fmt.Sprintf("IPv4: %s, IPv6: %s", ipv4, ipv6)
	}

	result.Duration = time.Since(start)
	ts.addResult(result)
}

func (ts *TestSuite) testDNSResolution() {
	start := time.Now()
	result := TestResult{
		Name:      "DNS Resolution",
		Timestamp: start,
	}

	// Try to resolve google.com
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(ctx, "google.com")
	if err != nil {
		result.Success = false
		result.Error = err.Error()
	} else {
		result.Success = true
		result.Details = fmt.Sprintf("Resolved %d addresses: %v", len(addrs), addrs)
	}

	result.Duration = time.Since(start)
	ts.addResult(result)
}

func (ts *TestSuite) testHTTPConnection() {
	start := time.Now()
	result := TestResult{
		Name:      "HTTP Connection",
		Timestamp: start,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", "http://www.google.com", nil)
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
	} else {
		defer resp.Body.Close()
		result.Success = resp.StatusCode == 200
		result.Details = fmt.Sprintf("Status: %d %s", resp.StatusCode, resp.Status)
		if !result.Success {
			result.Error = fmt.Sprintf("Unexpected status code: %d", resp.StatusCode)
		}
	}

	result.Duration = time.Since(start)
	ts.addResult(result)
}

func (ts *TestSuite) testHTTPSConnection() {
	start := time.Now()
	result := TestResult{
		Name:      "HTTPS Connection",
		Timestamp: start,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.google.com", nil)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
	} else {
		defer resp.Body.Close()
		result.Success = resp.StatusCode == 200
		result.Details = fmt.Sprintf("Status: %d %s, TLS: %s", resp.StatusCode, resp.Status, resp.TLS.Version)
		if !result.Success {
			result.Error = fmt.Sprintf("Unexpected status code: %d", resp.StatusCode)
		}
	}

	result.Duration = time.Since(start)
	ts.addResult(result)
}

func (ts *TestSuite) testSpeed(duration time.Duration) {
	start := time.Now()
	result := TestResult{
		Name:      "Speed Test",
		Timestamp: start,
	}

	// Download from a speed test server
	ctx, cancel := context.WithTimeout(context.Background(), duration+5*time.Second)
	defer cancel()

	// Use cloudflare speed test endpoint (returns random data)
	url := "https://speed.cloudflare.com/__down?bytes=10000000" // 10MB
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	client := &http.Client{
		Timeout: duration + 5*time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		result.Duration = time.Since(start)
		ts.addResult(result)
		return
	}
	defer resp.Body.Close()

	// Read and measure speed
	buf := make([]byte, 32768)
	var totalBytes int64
	testStart := time.Now()
	testEnd := testStart.Add(duration)

	for time.Now().Before(testEnd) {
		n, err := resp.Body.Read(buf)
		if err != nil && err != io.EOF {
			break
		}
		totalBytes += int64(n)
		if err == io.EOF {
			break
		}
	}

	elapsed := time.Since(testStart)
	if totalBytes > 0 {
		result.Success = true
		mbps := float64(totalBytes*8) / elapsed.Seconds() / 1000000
		result.Details = fmt.Sprintf("Downloaded %.2f MB in %v (%.2f Mbps)", float64(totalBytes)/1000000, elapsed, mbps)
	} else {
		result.Success = false
		result.Error = "No data received"
	}

	result.Duration = time.Since(start)
	ts.addResult(result)
}

func (ts *TestSuite) testLatency() {
	start := time.Now()
	result := TestResult{
		Name:      "Latency Test",
		Timestamp: start,
	}

	// Ping Cloudflare DNS
	var latencies []time.Duration
	for i := 0; i < 10; i++ {
		pingStart := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)

		req, _ := http.NewRequestWithContext(ctx, "HEAD", "https://1.1.1.1", nil)
		client := &http.Client{
			Timeout: 2 * time.Second,
		}

		resp, err := client.Do(req)
		cancel()

		if err == nil {
			resp.Body.Close()
			latency := time.Since(pingStart)
			latencies = append(latencies, latency)
		}

		time.Sleep(100 * time.Millisecond)
	}

	if len(latencies) > 0 {
		var total time.Duration
		min := latencies[0]
		max := latencies[0]

		for _, l := range latencies {
			total += l
			if l < min {
				min = l
			}
			if l > max {
				max = l
			}
		}

		avg := total / time.Duration(len(latencies))
		result.Success = true
		result.Details = fmt.Sprintf("Min: %v, Avg: %v, Max: %v (%d/%d successful)", min, avg, max, len(latencies), 10)
	} else {
		result.Success = false
		result.Error = "All ping attempts failed"
	}

	result.Duration = time.Since(start)
	ts.addResult(result)
}

func (ts *TestSuite) testStability(duration time.Duration) {
	start := time.Now()
	result := TestResult{
		Name:      "Stability Test",
		Timestamp: start,
	}

	testEnd := time.Now().Add(duration)
	successCount := 0
	failCount := 0
	totalAttempts := 0

	for time.Now().Before(testEnd) {
		totalAttempts++

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://detectportal.firefox.com/success.txt", nil)
		client := &http.Client{
			Timeout: 3 * time.Second,
		}

		resp, err := client.Do(req)
		cancel()

		if err == nil && resp.StatusCode == 200 {
			successCount++
			resp.Body.Close()
		} else {
			failCount++
		}

		time.Sleep(1 * time.Second)
	}

	successRate := float64(successCount) / float64(totalAttempts) * 100
	result.Success = successRate >= 95.0
	result.Details = fmt.Sprintf("Success: %d/%d (%.1f%%), Failed: %d", successCount, totalAttempts, successRate, failCount)

	if !result.Success {
		result.Error = fmt.Sprintf("Success rate %.1f%% below threshold (95%%)", successRate)
	}

	result.Duration = time.Since(start)
	ts.addResult(result)
}

func (ts *TestSuite) addResult(result TestResult) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.results = append(ts.results, result)

	if ts.verbose {
		if result.Success {
			fmt.Printf("✅ %s: PASSED (%v)\n", result.Name, result.Duration)
			if result.Details != "" {
				fmt.Printf("   %s\n", result.Details)
			}
		} else {
			fmt.Printf("❌ %s: FAILED (%v)\n", result.Name, result.Duration)
			fmt.Printf("   Error: %s\n", result.Error)
		}
	}
}

func (ts *TestSuite) outputSummary() {
	fmt.Println("\n═══════════════════════════════════════════════════════════")
	fmt.Println("📊 TEST RESULTS SUMMARY")
	fmt.Println("═══════════════════════════════════════════════════════════")

	passed := 0
	failed := 0
	var totalDuration time.Duration

	for _, r := range ts.results {
		status := "✅"
		statusText := "PASSED"
		if !r.Success {
			status = "❌"
			statusText = "FAILED"
			failed++
		} else {
			passed++
		}
		totalDuration += r.Duration

		fmt.Printf("\n%s %s: %s (%v)\n", status, r.Name, statusText, r.Duration)
		if r.Details != "" {
			fmt.Printf("   %s\n", r.Details)
		}
		if r.Error != "" {
			fmt.Printf("   Error: %s\n", r.Error)
		}
	}

	fmt.Println("\n═══════════════════════════════════════════════════════════")
	fmt.Printf("📈 Total: %d tests | ✅ Passed: %d | ❌ Failed: %d\n", len(ts.results), passed, failed)
	fmt.Printf("⏱️  Total Duration: %v\n", totalDuration)

	if failed == 0 {
		fmt.Println("🎉 All tests passed!")
	} else {
		fmt.Printf("⚠️  %d test(s) failed\n", failed)
	}
	fmt.Println("═══════════════════════════════════════════════════════════")
}

func (ts *TestSuite) outputJSON() {
	output := struct {
		Timestamp time.Time    `json:"timestamp"`
		Total     int          `json:"total"`
		Passed    int          `json:"passed"`
		Failed    int          `json:"failed"`
		Results   []TestResult `json:"results"`
	}{
		Timestamp: time.Now(),
		Results:   ts.results,
	}

	for _, r := range ts.results {
		output.Total++
		if r.Success {
			output.Passed++
		} else {
			output.Failed++
		}
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(output)
}

func printBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════╗
║        MASQUE Connection Test Suite                      ║
║        Comprehensive Testing Tool for vwarp               ║
╚═══════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}
