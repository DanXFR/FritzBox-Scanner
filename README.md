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

bash
# Uses 192.168.178.1 by default
./fritzbox-scanner

# Or specify a different IP/hostname
./fritzbox-scanner 192.168.178.254

./fritzbox-scanner fritz.box

