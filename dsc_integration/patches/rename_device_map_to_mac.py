import frappe

def execute():
    devices = frappe.get_all("HNS Device Map", fields=["name", "mac_address"])
    
    for device in devices:
        if device.mac_address and device.name != device.mac_address:
            try:
                frappe.rename_doc("HNS Device Map", device.name, device.mac_address, force=True)
                frappe.db.commit()
            except Exception as e:
                frappe.log_error(title=f"Failed to rename {device.name} to {device.mac_address}", message=frappe.get_traceback())
