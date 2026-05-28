package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

const Version = "4.1.0"

// ============================================================================
// CONFIG
// ============================================================================

type Config struct {
	InputFile      string
	Single         string
	OutputFile     string
	CSVExport      string
	JSONExport     string
	Workers        int
	Timeout        time.Duration
	Retries        int
	Verbose        bool
	Silent         bool
	DNSServer      string
	ShowVulnerable bool
	ShowSecure     bool
	ReportFormat   string
}

// ============================================================================
// RESULT
// ============================================================================

type Result struct {
	Domain               string
	SPFStatus            string
	SPFPriority          string
	SPFRecord            string
	DMARCStatus          string
	DMARCPriority        string
	DMARCRecord          string
	DMARCPolicy          string
	DKIMStatus           string
	DKIMRecord           string
	OverallVulnerability string
	RiskScore            int
	Timestamp            string
	ScanTime             time.Duration
	Error                string
}

// ============================================================================
// STATISTICS
// ============================================================================

type Statistics struct {
	TotalDomains     int
	Vulnerable       int
	AtRisk           int
	Secure           int
	Errors           int
	TotalTime        time.Duration
	AverageScanTime  time.Duration
	HighestRisk      string
	RiskDistribution map[string]int
}

// ============================================================================
// LOGGER
// ============================================================================

type Logger struct {
	Verbose bool
	mu      sync.Mutex
}

func NewLogger(verbose bool) *Logger {
	return &Logger{
		Verbose: verbose,
	}
}

func (l *Logger) Info(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	color.Cyan("[*] %s\n", msg)
}

func (l *Logger) Success(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	color.Green("[+] %s\n", msg)
}

func (l *Logger) Warning(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	color.Yellow("[!] %s\n", msg)
}

func (l *Logger) Error(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	color.Red("[-] %s\n", msg)
}

func (l *Logger) Debug(msg string) {
	if l.Verbose {
		l.mu.Lock()
		defer l.mu.Unlock()

		color.Magenta("[DEBUG] %s\n", msg)
	}
}

func (l *Logger) Progress(current, total int, domain string) {
	if !l.Verbose {
		fmt.Printf("\r[*] [%d/%d] %-40s", current, total, domain)
	}
}

func (l *Logger) Newline() {
	fmt.Println()
}

func (l *Logger) Banner() {
	banner := `
 __  __       _ _   __  __ _                     __ _       
|  \/  |     (_) | |  \/  (_)                   / _(_)      
| \  / | __ _ _| | | \  / |_ ___  ___ ___  _ __| |_ _  __ _ 
| |\/| |/ _  | | | | |\/| | / __|/ __/ _ \| '__|  _| |/ _  |
| |  | | (_| | | | | |  | | \__ \ (_| (_) | |  | | | | (_| |
|_|  |_|\__,_|_|_| |_|  |_|_|___/\___\___/|_|  |_| |_|\__, |
                                                        __/ |
                                                       |___/

MAIL-MISCONFIG v4.1.0
`
	fmt.Println(banner)
}

// ============================================================================
// HELPERS
// ============================================================================

func isValidDomain(domain string) bool {
	domain = strings.TrimSpace(strings.ToLower(domain))

	if domain == "" {
		return false
	}

	matched, _ := regexp.MatchString(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`, domain)

	return matched
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}

	return s[:n] + "..."
}

// ============================================================================
// DNS LOOKUP
// ============================================================================

func lookupTXT(domain string, timeout time.Duration, retries int, dnsServer string) ([]string, error) {

	var txtRecords []string
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for attempt := 0; attempt <= retries; attempt++ {

		var resolver *net.Resolver

		if dnsServer != "" {

			resolver = &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {

					d := net.Dialer{
						Timeout: timeout,
					}

					return d.DialContext(ctx, "udp", dnsServer+":53")
				},
			}

		} else {

			resolver = net.DefaultResolver
		}

		txtRecords, err = resolver.LookupTXT(ctx, domain)

		if err == nil {
			return txtRecords, nil
		}

		time.Sleep(300 * time.Millisecond)
	}

	return nil, err
}

// ============================================================================
// SPF
// ============================================================================

func checkSPF(domain string, timeout time.Duration, retries int, dnsServer string) (string, string, string, int) {

	status := "MISSING"
	priority := "P3"
	record := "No SPF record found"
	risk := 50

	txtRecords, err := lookupTXT(domain, timeout, retries, dnsServer)

	if err != nil {
		return status, priority, record, risk
	}

	for _, r := range txtRecords {

		r = strings.TrimSpace(strings.ToLower(r))

		if strings.HasPrefix(r, "v=spf1") {

			record = truncate(r, 150)

			fields := strings.Fields(r)

			lastField := ""

			if len(fields) > 0 {
				lastField = fields[len(fields)-1]
			}

			switch lastField {

			case "+all":
				status = "VULNERABLE"
				priority = "P1"
				risk = 100

			case "~all":
				status = "WARNING"
				priority = "P3"
				risk = 45

			case "?all":
				status = "WARNING"
				priority = "P3"
				risk = 60

			case "-all":
				status = "SECURE"
				priority = "PASS"
				risk = 5

			default:
				status = "WEAK"
				priority = "P3"
				risk = 35
			}

			return status, priority, record, risk
		}
	}

	return status, priority, record, risk
}

// ============================================================================
// DMARC
// ============================================================================

func parseDMARCTags(record string) map[string]string {

	tags := make(map[string]string)

	parts := strings.Split(record, ";")

	for _, p := range parts {

		p = strings.TrimSpace(p)

		if strings.Contains(p, "=") {

			kv := strings.SplitN(p, "=", 2)

			if len(kv) == 2 {

				key := strings.TrimSpace(strings.ToLower(kv[0]))
				val := strings.TrimSpace(strings.ToLower(kv[1]))

				tags[key] = val
			}
		}
	}

	return tags
}

func checkDMARC(domain string, timeout time.Duration, retries int, dnsServer string) (string, string, string, string, int) {

	status := "MISSING"
	priority := "P4"
	record := "No DMARC record found"
	policy := "none"
	risk := 60

	domain = "_dmarc." + domain

	txtRecords, err := lookupTXT(domain, timeout, retries, dnsServer)

	if err != nil {
		return status, priority, record, policy, risk
	}

	for _, r := range txtRecords {

		r = strings.TrimSpace(strings.ToLower(r))

		if strings.HasPrefix(r, "v=dmarc1") {

			record = truncate(r, 150)

			tags := parseDMARCTags(r)

			policy = tags["p"]

			switch policy {

			case "reject":
				status = "SECURE"
				priority = "PASS"
				risk = 5

			case "quarantine":
				status = "OK"
				priority = "PASS"
				risk = 20

			case "none":
				status = "WARNING"
				priority = "P4"
				risk = 50

			default:
				status = "INVALID"
				priority = "P2"
				risk = 70
			}

			return status, priority, record, policy, risk
		}
	}

	return status, priority, record, policy, risk
}

// ============================================================================
// DKIM
// ============================================================================

func checkDKIM(domain string, timeout time.Duration, retries int, dnsServer string) (string, string, int) {

	selectors := []string{
		"default",
		"selector1",
		"selector2",
		"google",
		"k1",
		"k2",
		"mail",
		"dkim",
		"smtp",
		"amazonses",
		"sendgrid",
	}

	for _, selector := range selectors {

		target := fmt.Sprintf("%s._domainkey.%s", selector, domain)

		txtRecords, err := lookupTXT(target, timeout, retries, dnsServer)

		if err != nil {
			continue
		}

		for _, r := range txtRecords {

			r = strings.ToLower(r)

			if strings.Contains(r, "v=dkim1") {

				return "FOUND", truncate(r, 150), 5
			}
		}
	}

	return "MISSING", "No DKIM record found", 20
}

// ============================================================================
// RISK
// ============================================================================

func calculateRiskScore(spfRisk, dmarcRisk, dkimRisk int) int {

	score := (spfRisk * 40 / 100) +
		(dmarcRisk * 40 / 100) +
		(dkimRisk * 20 / 100)

	if spfRisk >= 100 {
		return 95
	}

	if score > 100 {
		score = 100
	}

	return score
}

func assessVulnerability(risk int) string {

	if risk >= 70 {
		return "VULNERABLE"
	}

	if risk >= 30 {
		return "AT_RISK"
	}

	return "SECURE"
}

// ============================================================================
// SCAN
// ============================================================================

func scanDomain(domain string, cfg *Config) Result {

	start := time.Now()

	domain = strings.TrimSpace(strings.ToLower(domain))

	if !isValidDomain(domain) {

		return Result{
			Domain: domain,
			Error:  "invalid domain",
		}
	}

	spfStatus, spfPriority, spfRecord, spfRisk :=
		checkSPF(domain, cfg.Timeout, cfg.Retries, cfg.DNSServer)

	dmarcStatus, dmarcPriority, dmarcRecord, dmarcPolicy, dmarcRisk :=
		checkDMARC(domain, cfg.Timeout, cfg.Retries, cfg.DNSServer)

	dkimStatus, dkimRecord, dkimRisk :=
		checkDKIM(domain, cfg.Timeout, cfg.Retries, cfg.DNSServer)

	risk := calculateRiskScore(spfRisk, dmarcRisk, dkimRisk)

	return Result{
		Domain:               domain,
		SPFStatus:            spfStatus,
		SPFPriority:          spfPriority,
		SPFRecord:            spfRecord,
		DMARCStatus:          dmarcStatus,
		DMARCPriority:        dmarcPriority,
		DMARCRecord:          dmarcRecord,
		DMARCPolicy:          dmarcPolicy,
		DKIMStatus:           dkimStatus,
		DKIMRecord:           dkimRecord,
		OverallVulnerability: assessVulnerability(risk),
		RiskScore:            risk,
		Timestamp:            time.Now().Format(time.RFC3339),
		ScanTime:             time.Since(start),
	}
}

// ============================================================================
// CONCURRENT SCAN
// ============================================================================

func scanConcurrent(domains []string, cfg *Config, logger *Logger) []Result {

	domainChan := make(chan string)
	resultChan := make(chan Result)

	var wg sync.WaitGroup

	for i := 0; i < cfg.Workers; i++ {

		wg.Add(1)

		go func() {

			defer wg.Done()

			for domain := range domainChan {

				result := scanDomain(domain, cfg)

				resultChan <- result
			}
		}()
	}

	go func() {

		for i, domain := range domains {

			logger.Progress(i+1, len(domains), domain)

			domainChan <- domain
		}

		close(domainChan)
	}()

	go func() {

		wg.Wait()

		close(resultChan)
	}()

	results := make([]Result, 0, len(domains))

	for result := range resultChan {
		results = append(results, result)
	}

	logger.Newline()

	return results
}

// ============================================================================
// STATS
// ============================================================================

func calculateStatistics(results []Result) Statistics {

	stats := Statistics{
		TotalDomains:     len(results),
		RiskDistribution: make(map[string]int),
	}

	var total time.Duration

	highest := 0

	for _, r := range results {

		if r.Error != "" {
			stats.Errors++
			continue
		}

		total += r.ScanTime

		switch r.OverallVulnerability {

		case "VULNERABLE":
			stats.Vulnerable++

		case "AT_RISK":
			stats.AtRisk++

		case "SECURE":
			stats.Secure++
		}

		stats.RiskDistribution[r.OverallVulnerability]++

		if r.RiskScore > highest {

			highest = r.RiskScore
			stats.HighestRisk = r.Domain
		}
	}

	stats.TotalTime = total

	if stats.TotalDomains > 0 {
		stats.AverageScanTime = total / time.Duration(stats.TotalDomains)
	}

	return stats
}

// ============================================================================
// CSV
// ============================================================================

func exportCSV(results []Result, fileName string) error {

	file, err := os.Create(fileName)

	if err != nil {
		return err
	}

	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{
		"Domain",
		"SPF_Status",
		"DMARC_Status",
		"DMARC_Policy",
		"DKIM_Status",
		"Risk_Score",
		"Vulnerability",
	}

	writer.Write(headers)

	for _, r := range results {

		if r.Error != "" {
			continue
		}

		row := []string{
			r.Domain,
			r.SPFStatus,
			r.DMARCStatus,
			r.DMARCPolicy,
			r.DKIMStatus,
			fmt.Sprintf("%d", r.RiskScore),
			r.OverallVulnerability,
		}

		writer.Write(row)
	}

	return nil
}

// ============================================================================
// JSON
// ============================================================================

func exportJSON(results []Result, fileName string) error {

	file, err := os.Create(fileName)

	if err != nil {
		return err
	}

	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	return encoder.Encode(results)
}

// ============================================================================
// FILE INPUT
// ============================================================================

func readDomains(fileName string) ([]string, error) {

	file, err := os.Open(fileName)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	var domains []string

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#") {
			continue
		}

		domains = append(domains, line)
	}

	return domains, nil
}

// ============================================================================
// REPORT
// ============================================================================

func printResults(results []Result, stats Statistics) {

	sort.Slice(results, func(i, j int) bool {
		return results[i].RiskScore > results[j].RiskScore
	})

	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))

	fmt.Printf("Total Domains: %d\n", stats.TotalDomains)
	fmt.Printf("Vulnerable: %d\n", stats.Vulnerable)
	fmt.Printf("At Risk: %d\n", stats.AtRisk)
	fmt.Printf("Secure: %d\n", stats.Secure)
	fmt.Printf("Errors: %d\n", stats.Errors)
	fmt.Printf("Average Scan Time: %v\n", stats.AverageScanTime)

	fmt.Println(strings.Repeat("=", 80))

	for _, r := range results {

		if r.Error != "" {
			continue
		}

		fmt.Printf("\n[%d/100] %s\n", r.RiskScore, r.Domain)

		fmt.Printf(" SPF   : %s\n", r.SPFStatus)
		fmt.Printf(" DMARC : %s (%s)\n", r.DMARCStatus, r.DMARCPolicy)
		fmt.Printf(" DKIM  : %s\n", r.DKIMStatus)
		fmt.Printf(" Status: %s\n", r.OverallVulnerability)
	}
}

// ============================================================================
// FLAGS
// ============================================================================

func parseFlags() *Config {

	cfg := &Config{}

	flag.StringVar(&cfg.InputFile, "input", "", "Input file")
	flag.StringVar(&cfg.Single, "single", "", "Single domain")
	flag.StringVar(&cfg.CSVExport, "csv", "", "CSV export")
	flag.StringVar(&cfg.JSONExport, "json", "", "JSON export")
	flag.IntVar(&cfg.Workers, "workers", 20, "Workers")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "Timeout")
	flag.IntVar(&cfg.Retries, "retries", 2, "Retries")
	flag.StringVar(&cfg.DNSServer, "dns", "", "Custom DNS")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose")

	flag.Parse()

	return cfg
}

// ============================================================================
// MAIN
// ============================================================================

func main() {

	cfg := parseFlags()

	logger := NewLogger(cfg.Verbose)

	logger.Banner()

	var domains []string

	if cfg.Single != "" {

		domains = []string{cfg.Single}

	} else {

		if cfg.InputFile == "" {

			logger.Error("provide -input or -single")

			os.Exit(1)
		}

		d, err := readDomains(cfg.InputFile)

		if err != nil {

			logger.Error(err.Error())

			os.Exit(1)
		}

		domains = d
	}

	var valid []string

	for _, d := range domains {

		if isValidDomain(d) {
			valid = append(valid, d)
		}
	}

	if len(valid) == 0 {

		logger.Error("no valid domains")

		os.Exit(1)
	}

	logger.Info(fmt.Sprintf("Loaded %d domains", len(valid)))

	start := time.Now()

	results := scanConcurrent(valid, cfg, logger)

	stats := calculateStatistics(results)

	stats.TotalTime = time.Since(start)

	printResults(results, stats)

	if cfg.CSVExport != "" {

		err := exportCSV(results, cfg.CSVExport)

		if err == nil {
			logger.Success("CSV exported")
		}
	}

	if cfg.JSONExport != "" {

		err := exportJSON(results, cfg.JSONExport)

		if err == nil {
			logger.Success("JSON exported")
		}
	}

	logger.Success(fmt.Sprintf("Completed in %v", stats.TotalTime))
}
