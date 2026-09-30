//go:build windows

package main

import (
	"net"
	"os/exec"
	"strings"
	"syscall"
)

var cachedMacAddress string

func getMacAddress() string {
	if cachedMacAddress != "" {
		return cachedMacAddress
	}

	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
		`Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true } | Select-Object -First 1 -ExpandProperty MacAddress`)
	
	// Hide the powershell window on Windows!
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	out, err := cmd.Output()
	if err == nil {
		mac := strings.TrimSpace(string(out))
		if mac != "" {
			mac = strings.ReplaceAll(mac, "-", ":")
			cachedMacAddress = strings.ToUpper(mac)
			return cachedMacAddress
		}
	}

	// Fallback logic
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, i := range interfaces {
			name := strings.ToLower(i.Name)
			if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) == 0 {
				continue
			}
			if strings.Contains(name, "wsl") || strings.Contains(name, "tailscale") || strings.Contains(name, "vethernet") || strings.Contains(name, "hyper") || strings.Contains(name, "vmware") || strings.Contains(name, "virtual") || strings.Contains(name, "pseudo") || strings.Contains(name, "vpn") {
				continue
			}
			cachedMacAddress = strings.ToUpper(i.HardwareAddr.String())
			return cachedMacAddress
		}
	}
	return ""
}
