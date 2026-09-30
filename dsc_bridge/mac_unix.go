//go:build !windows

package main

import (
	"net"
	"strings"
)

var cachedMacAddress string

func getMacAddress() string {
	if cachedMacAddress != "" {
		return cachedMacAddress
	}

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
