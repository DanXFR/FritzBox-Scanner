# FritzBox-Scanner
Golang script which checks the security status of a FritzBox.
The scanner  performs 16 comprehensive security checks covering network protocols, wireless security, remote access, file sharing, and VoIP security. Each check includes appropriate severity levels (HIGH, MEDIUM, INFO) to help prioritize remediation efforts.

Key Features:

No external dependencies - uses only Go standard library
Concurrent-safe scanning
Cross-platform compatible (Windows, Linux, macOS)
Compiled binary for easy distribution

Advantages of the Go version:

Single binary - no need to install dependencies
Faster execution - compiled code is more performant
Smaller footprint - can run on embedded systems
Easy deployment - just copy the binary

To compile for different platforms:
# Linux
GOOS=linux GOARCH=amd64 go build -o fritzbox-scanner-linux

# Windows
GOOS=windows GOARCH=amd64 go build -o fritzbox-scanner.exe

# macOS
GOOS=darwin GOARCH=amd64 go build -o fritzbox-scanner-mac

The script uses 192.168.178.1 as a default IP

# Uses 192.168.178.1 (standard FritzBox IP) by default
./fritzbox-scanner (Linux) 

fritzbox-scanner.exe (Windows)

# Or specify a different IP/hostname
./fritzbox-scanner 192.168.178.254

./fritzbox-scanner fritz.box

# Current Features
Connectivity Checks - Verifies device is reachable

HTTPS/SSL Testing - Checks if encrypted access is available

Default Credentials - Tests for weak authentication

Port Scanning - Identifies open ports and insecure protocols (FTP, Telnet)

UPnP Detection - Checks for UPnP exposure

Firmware Information - Attempts to detect version infp

Remote Access Check - Reminds you to verify remote access settings

WPS (WiFi Protected Setup) - Checks for WPS vulnerability to brute-force attacks

DNS Rebinding Protection - Tests if the device is protected against DNS rebinding attacks

TR-064 Protocol Exposure - Scans for exposed TR-064 ports (49000, 49443) which should not be internet-facing

MyFRITZ! Service - Reminds to secure remote access with strong passwords and 2FA

WiFi Encryption - Verifies proper encryption standards (WPA3/WPA2-AES)

Guest Network Configuration - Checks guest network isolation settings

IPv6 Firewall - Detects IPv6 and warns about proper firewall configuration

SIP/VoIP Security - Scans port 5060 and warns about SIP account password strength

USB Storage Security - Checks SMB and FTP file sharing for USB devices

Automatic Updates - Reminds to enable automatic firmware updates
