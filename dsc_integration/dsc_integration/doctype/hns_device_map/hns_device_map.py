# Copyright (c) 2026, HNS and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document
import subprocess
import re
class HNSDeviceMap(Document):
	def before_insert(self):
		self.created_at = frappe.utils.now_datetime()
		self.created_by = frappe.session.user
		
	def before_save(self):
		self.modifie_at = frappe.utils.now_datetime()
		self.modifie_by = frappe.session.user

@frappe.whitelist()
def get_physical_mac():
    command = [
        'powershell.exe',
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-Command',
        '''
        $Mac = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true } | Select-Object -First 1 -ExpandProperty MacAddress
        $Mac = if ($Mac) { $Mac -replace '-', ':' } else { '' }
        
        $ComputerSystem = Get-CimInstance Win32_ComputerSystem
        $Enclosure = Get-CimInstance Win32_SystemEnclosure | Select-Object -First 1
        $Chassis = if ($Enclosure) { $Enclosure.ChassisTypes[0] } else { 0 }
        
        $DeviceType = 'Desktop'
        if ($Chassis -in 8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32) {
            $DeviceType = 'Laptop'
        }
        
        $data = @{
            mac_address = $Mac
            person_name = $ComputerSystem.Name
            device_name = $ComputerSystem.Name
            os = 'Window'
            device_type = $DeviceType
        }
        $data | ConvertTo-Json
        '''
    ]

    try:
        import json
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return None
        
        data = json.loads(result.stdout.strip())
        return data
    except Exception as e:
        frappe.log_error("MAC Fetch Error", str(e))
        return None
