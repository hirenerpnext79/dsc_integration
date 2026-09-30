# Copyright (c) 2026, HNS and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document
import subprocess
import re

class HNSDeviceMap(Document):
	pass

@frappe.whitelist()
def get_physical_mac():
    """
    Return the MAC address of an active physical Ethernet/Wi-Fi adapter.

    Ignores:
    - Hyper-V
    - WSL
    - Tailscale
    - VPN
    - Other virtual adapters
    """

    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        """
        Get-NetAdapter |
        Where-Object {
            $_.Status -eq 'Up' -and
            $_.HardwareInterface -eq $true
        } |
        Select-Object -First 1 -ExpandProperty MacAddress
        """
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )

        mac = result.stdout.strip()

        if not mac:
            raise RuntimeError("No active physical network adapter found")

        # Normalize to XX:XX:XX:XX:XX:XX
        mac = mac.replace("-", ":").upper()

        if not re.fullmatch(
            r"[0-9A-F]{2}(:[0-9A-F]{2}){5}",
            mac
        ):
            raise RuntimeError(f"Invalid MAC address returned: {mac}")

        return mac
    except Exception as e:
        frappe.log_error("MAC Fetch Error", str(e))
        return None
