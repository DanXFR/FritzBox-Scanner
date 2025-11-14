package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Severity levels
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityInfo   = "info"
)

// ScanResult represents a single security check result
type ScanResult struct {
	Category  string
	Status    string
	Message   string
	Severity  string
	Timestamp time.Time
}

// FritzBoxScanner holds scanner configuration and results
type FritzBoxScanner struct {
	Host     string
	BaseURL  string
	HTTPSURL string
	Results  []ScanResult
}

// NewFritzBoxScanner creates a new scanner instance
func NewFritzBoxScanner(host string) *FritzBoxScanner {
	if host == "" {
		host = "192.168.178.1"
	}
	return &FritzBoxScanner{
		Host:     host,
		BaseURL:  fmt.Sprintf("http://%s", host),
		HTTPSURL: fmt.Sprintf("https://%s", host),
		Results:  make([]ScanResult, 0),
	}
}

// AddResult adds a check result
func (s *FritzBoxScanner) AddResult(category, status, message, severity string) {
	s.Results = append(s.Results, ScanResult{
		Category:  category,
		Status:    status,
		Message:   message,
		Severity:  severity,
		Timestamp: time.Now(),
	})
}

// CheckReachability checks if Fritz!Box is reachable
func (s *FritzBoxScanner) CheckReachability() bool {
	fmt.Println("[*] Checking device reachability...")

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	resp, err := client.Get(s.BaseURL)
	if err != nil {
		s.AddResult("Connectivity", "FAIL",
			fmt.Sprintf("Cannot reach device: %v", err), SeverityHigh)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 302 {
		s.AddResult("Connectivity", "PASS",
			fmt.Sprintf("Device is reachable at %s", s.Host), SeverityInfo)
		return true
	}

	s.AddResult("Connectivity", "FAIL",
		fmt.Sprintf("Unexpected status code: %d", resp.StatusCode), SeverityHigh)
	return false
}

// CheckHTTPSAvailable checks if HTTPS is available and certificate validity
func (s *FritzBoxScanner) CheckHTTPSAvailable() bool {
	fmt.Println("[*] Checking HTTPS availability...")

	// Create client that skips certificate verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(s.HTTPSURL)
	if err != nil {
		s.AddResult("HTTPS", "WARNING",
			fmt.Sprintf("HTTPS not available or certificate issue: %v", err), SeverityMedium)
		return false
	}
	defer resp.Body.Close()

	s.AddResult("HTTPS", "PASS", "HTTPS is available", SeverityInfo)

	// Check certificate details
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", s.Host), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err == nil {
		defer conn.Close()
		certs := conn.ConnectionState().PeerCertificates
		if len(certs) > 0 {
			s.AddResult("SSL Certificate", "WARNING",
				"Certificate present but validity should be verified manually", SeverityMedium)
		}
	}

	return true
}

// CheckDefaultCredentials checks for default login page access
func (s *FritzBoxScanner) CheckDefaultCredentials() {
	fmt.Println("[*] Checking for default credentials...")

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(fmt.Sprintf("%s/login_sid.lua", s.BaseURL))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			s.AddResult("Default Credentials", "WARNING",
				"Login page accessible - ensure strong password is set", SeverityHigh)
		}
	}
}

// CheckOpenPorts scans common ports
func (s *FritzBoxScanner) CheckOpenPorts() {
	fmt.Println("[*] Scanning common ports...")

	commonPorts := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		80:   "HTTP",
		443:  "HTTPS",
		445:  "SMB",
		8080: "HTTP-Alt",
		8443: "HTTPS-Alt",
	}

	openPorts := []string{}
	insecurePorts := []int{}

	for port, service := range commonPorts {
		address := fmt.Sprintf("%s:%d", s.Host, port)
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			conn.Close()
			openPorts = append(openPorts, fmt.Sprintf("%d (%s)", port, service))

			// Track insecure protocols
			if port == 21 || port == 23 {
				insecurePorts = append(insecurePorts, port)
			}
		}
	}

	if len(openPorts) > 0 {
		s.AddResult("Open Ports", "INFO",
			fmt.Sprintf("Open ports detected: %s", strings.Join(openPorts, ", ")), SeverityInfo)
	}

	// Check for insecure protocols
	for _, port := range insecurePorts {
		if port == 21 {
			s.AddResult("Insecure Protocol", "FAIL",
				"FTP port is open - use SFTP instead", SeverityHigh)
		} else if port == 23 {
			s.AddResult("Insecure Protocol", "FAIL",
				"Telnet port is open - use SSH instead", SeverityHigh)
		}
	}
}

// CheckUPnP checks if UPnP is exposed
func (s *FritzBoxScanner) CheckUPnP() {
	fmt.Println("[*] Checking UPnP exposure...")

	addr, err := net.ResolveUDPAddr("udp", "239.255.255.250:1900")
	if err != nil {
		s.AddResult("UPnP", "INFO",
			fmt.Sprintf("Could not check UPnP: %v", err), SeverityInfo)
		return
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		s.AddResult("UPnP", "INFO",
			fmt.Sprintf("Could not check UPnP: %v", err), SeverityInfo)
		return
	}
	defer conn.Close()

	msg := []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST:239.255.255.250:1900\r\n" +
		"ST:upnp:rootdevice\r\n" +
		"MX:2\r\n" +
		"MAN:\"ssdp:discover\"\r\n" +
		"\r\n")

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write(msg)
	if err != nil {
		s.AddResult("UPnP", "INFO",
			fmt.Sprintf("Could not check UPnP: %v", err), SeverityInfo)
		return
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		s.AddResult("UPnP", "WARNING",
			"UPnP service detected - ensure it's needed and properly configured", SeverityMedium)
	} else {
		s.AddResult("UPnP", "PASS",
			"UPnP not detected or not responding", SeverityInfo)
	}
}

// CheckRemoteAccess reminds to check remote access
func (s *FritzBoxScanner) CheckRemoteAccess() {
	fmt.Println("[*] Checking remote access configuration...")
	s.AddResult("Remote Access", "MANUAL",
		"Please manually verify remote access is disabled if not needed", SeverityMedium)
}

// CheckFirmwareInfo tries to detect firmware version
func (s *FritzBoxScanner) CheckFirmwareInfo() {
	fmt.Println("[*] Checking firmware information...")

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(s.BaseURL)
	if err != nil {
		s.AddResult("Firmware", "INFO",
			fmt.Sprintf("Could not check firmware: %v", err), SeverityInfo)
		return
	}
	defer resp.Body.Close()

	serverHeader := resp.Header.Get("Server")

	if strings.Contains(serverHeader, "FRITZ") || strings.Contains(serverHeader, "AVM") {
		s.AddResult("Firmware", "MANUAL",
			"Fritz!Box detected - check https://en.avm.de/service/fritzbox/ for latest firmware", SeverityHigh)
	} else {
		s.AddResult("Firmware", "INFO",
			"Could not automatically detect firmware version", SeverityInfo)
	}
}

// CheckWPSEnabled checks if WPS is accessible (security risk)
func (s *FritzBoxScanner) CheckWPSEnabled() {
	fmt.Println("[*] Checking WPS status...")
	s.AddResult("WPS (WiFi Protected Setup)", "MANUAL",
		"WPS can be vulnerable to brute-force attacks - disable if not needed", SeverityMedium)
}

// CheckDNSRebinding checks for DNS rebinding protection
func (s *FritzBoxScanner) CheckDNSRebinding() {
	fmt.Println("[*] Checking DNS rebinding protection...")

	// Try to access with localhost
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Fritz!Box should reject requests with Host header != expected
	req, _ := http.NewRequest("GET", s.BaseURL, nil)
	req.Host = "attacker.com"

	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			s.AddResult("DNS Rebinding Protection", "FAIL",
				"Device may be vulnerable to DNS rebinding attacks", SeverityHigh)
		} else {
			s.AddResult("DNS Rebinding Protection", "PASS",
				"DNS rebinding protection appears active", SeverityInfo)
		}
	} else {
		s.AddResult("DNS Rebinding Protection", "INFO",
			"Could not verify DNS rebinding protection", SeverityInfo)
	}
}

// CheckTR064Exposure checks for TR-064 protocol exposure
func (s *FritzBoxScanner) CheckTR064Exposure() {
	fmt.Println("[*] Checking TR-064 protocol exposure...")

	tr064Ports := []int{49000, 49443}
	exposedPorts := []string{}

	for _, port := range tr064Ports {
		address := fmt.Sprintf("%s:%d", s.Host, port)
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			conn.Close()
			exposedPorts = append(exposedPorts, fmt.Sprintf("%d", port))
		}
	}

	if len(exposedPorts) > 0 {
		s.AddResult("TR-064 Protocol", "WARNING",
			fmt.Sprintf("TR-064 ports open (%s) - ensure not exposed to internet", strings.Join(exposedPorts, ", ")),
			SeverityMedium)
	} else {
		s.AddResult("TR-064 Protocol", "PASS",
			"TR-064 ports not accessible", SeverityInfo)
	}
}

// CheckMyFritzService checks MyFRITZ! service configuration
func (s *FritzBoxScanner) CheckMyFritzService() {
	fmt.Println("[*] Checking MyFRITZ! service...")
	s.AddResult("MyFRITZ! Service", "MANUAL",
		"If using MyFRITZ!, ensure strong password and 2FA are enabled", SeverityMedium)
}

// CheckWiFiEncryption checks WiFi security settings
func (s *FritzBoxScanner) CheckWiFiEncryption() {
	fmt.Println("[*] Checking WiFi encryption...")
	s.AddResult("WiFi Encryption", "MANUAL",
		"Verify WPA3 or at minimum WPA2-AES encryption is enabled (not WPA/TKIP)", SeverityHigh)
}

// CheckGuestNetwork checks guest network configuration
func (s *FritzBoxScanner) CheckGuestNetwork() {
	fmt.Println("[*] Checking guest network configuration...")
	s.AddResult("Guest Network", "MANUAL",
		"Ensure guest network is isolated from main network and has strong password", SeverityMedium)
}

// CheckIPv6Firewall checks IPv6 firewall status
func (s *FritzBoxScanner) CheckIPv6Firewall() {
	fmt.Println("[*] Checking IPv6 firewall...")

	// Try to connect via IPv6
	addrs, err := net.LookupIP(s.Host)
	hasIPv6 := false

	if err == nil {
		for _, addr := range addrs {
			if addr.To4() == nil {
				hasIPv6 = true
				break
			}
		}
	}

	if hasIPv6 {
		s.AddResult("IPv6 Firewall", "WARNING",
			"IPv6 detected - ensure firewall rules are properly configured for IPv6", SeverityMedium)
	} else {
		s.AddResult("IPv6 Firewall", "INFO",
			"IPv6 not detected or not configured", SeverityInfo)
	}
}

// CheckSIPSecurity checks SIP/VoIP security
func (s *FritzBoxScanner) CheckSIPSecurity() {
	fmt.Println("[*] Checking SIP/VoIP security...")

	sipPort := 5060
	address := fmt.Sprintf("%s:%d", s.Host, sipPort)
	conn, err := net.DialTimeout("tcp", address, 1*time.Second)

	if err == nil {
		conn.Close()
		s.AddResult("SIP Security", "WARNING",
			"SIP port 5060 is open - ensure SIP accounts have strong passwords", SeverityHigh)
	} else {
		s.AddResult("SIP Security", "PASS",
			"SIP port not accessible", SeverityInfo)
	}
}

// CheckUSBStorage checks USB storage sharing security
func (s *FritzBoxScanner) CheckUSBStorage() {
	fmt.Println("[*] Checking USB storage security...")

	// Check SMB port
	smbPort := 445
	ftpPort := 21

	address := fmt.Sprintf("%s:%d", s.Host, smbPort)
	conn, err := net.DialTimeout("tcp", address, 1*time.Second)

	if err == nil {
		conn.Close()
		s.AddResult("USB Storage (SMB)", "WARNING",
			"SMB file sharing detected - ensure password protection and disable if not needed", SeverityMedium)
	}

	// Check FTP for USB storage
	address = fmt.Sprintf("%s:%d", s.Host, ftpPort)
	conn, err = net.DialTimeout("tcp", address, 1*time.Second)

	if err == nil {
		conn.Close()
		s.AddResult("USB Storage (FTP)", "FAIL",
			"FTP for USB storage is insecure - use FTPS or disable", SeverityHigh)
	}
}

// CheckAutoUpdate checks if automatic updates are enabled
func (s *FritzBoxScanner) CheckAutoUpdate() {
	fmt.Println("[*] Checking automatic update configuration...")
	s.AddResult("Automatic Updates", "MANUAL",
		"Verify automatic updates are enabled in Fritz!Box settings for security patches", SeverityHigh)
}

// RunScan executes all security checks
func (s *FritzBoxScanner) RunScan() {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Fritz!Box Security Scanner")
	fmt.Printf("Target: %s\n", s.Host)
	fmt.Printf("Scan started: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	if !s.CheckReachability() {
		fmt.Println("\n[!] Device not reachable. Stopping scan.")
		return
	}

	s.CheckHTTPSAvailable()
	s.CheckDefaultCredentials()
	s.CheckOpenPorts()
	s.CheckUPnP()
	s.CheckRemoteAccess()
	s.CheckFirmwareInfo()
	s.CheckWPSEnabled()
	s.CheckDNSRebinding()
	s.CheckTR064Exposure()
	s.CheckMyFritzService()
	s.CheckWiFiEncryption()
	s.CheckGuestNetwork()
	s.CheckIPv6Firewall()
	s.CheckSIPSecurity()
	s.CheckUSBStorage()
	s.CheckAutoUpdate()

	s.PrintReport()
}

// PrintReport prints the security scan report
func (s *FritzBoxScanner) PrintReport() {
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Println("SECURITY SCAN REPORT")
	fmt.Printf("%s\n\n", strings.Repeat("=", 60))

	// Sort results by severity
	severityOrder := map[string]int{
		SeverityHigh:   0,
		SeverityMedium: 1,
		SeverityInfo:   2,
	}

	sort.Slice(s.Results, func(i, j int) bool {
		return severityOrder[s.Results[i].Severity] < severityOrder[s.Results[j].Severity]
	})

	criticalCount := 0
	warningCount := 0

	for _, result := range s.Results {
		if result.Severity == SeverityHigh {
			criticalCount++
		} else if result.Severity == SeverityMedium {
			warningCount++
		}
	}

	severitySymbols := map[string]string{
		SeverityHigh:   "[!]",
		SeverityMedium: "[*]",
		SeverityInfo:   "[+]",
	}

	for _, result := range s.Results {
		symbol := severitySymbols[result.Severity]
		if symbol == "" {
			symbol = "[-]"
		}

		severityLabel := strings.ToUpper(result.Severity)
		fmt.Printf("%s [%s] %s: %s\n", symbol, severityLabel, result.Category, result.Status)
		fmt.Printf("    %s\n\n", result.Message)
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Summary: %d critical, %d warnings\n", criticalCount, warningCount)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	fmt.Println("RECOMMENDATIONS:")
	fmt.Println("1. Update to the latest Fritz!OS firmware immediately")
	fmt.Println("2. Ensure a strong admin password is set")
	fmt.Println("3. Disable remote access if not needed")
	fmt.Println("4. Disable UPnP if not required")
	fmt.Println("5. Enable HTTPS-only access")
	fmt.Println("6. Regularly check for security updates")
	fmt.Println("7. Review and close unused port forwards")
	fmt.Println("8. Enable firewall logging for monitoring")
	fmt.Println("9. Use WPA3 or WPA2-AES encryption for WiFi")
	fmt.Println("10. Disable WPS if not actively needed")
	fmt.Println("11. Enable automatic firmware updates")
	fmt.Println("12. Use strong passwords for SIP/VoIP accounts")
	fmt.Println("13. Disable USB storage sharing if not required")
	fmt.Println("14. Enable guest network isolation")
	fmt.Println("15. Configure IPv6 firewall rules properly")
	fmt.Println("16. Disable TR-064 external access")
	fmt.Println("17. Enable 2FA for MyFRITZ! service if used")
	fmt.Println("18. Regularly review connected devices")
	fmt.Println("\nVisit: https://en.avm.de/service/fritzbox/ for updates and security bulletins")
}

func main() {
	fmt.Println("Fritz!Box Security Scanner v1.0")
	fmt.Println(strings.Repeat("=", 60))

	// Get target from command line or use default
	host := "192.168.178.1"
	if len(os.Args) > 1 {
		host = os.Args[1]
	}

	scanner := NewFritzBoxScanner(host)
	scanner.RunScan()
}
