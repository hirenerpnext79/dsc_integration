import frappe

def extend_bootinfo(bootinfo):
    try:
        format_settings = frappe.get_all("DSC Format Setting", fields=["ref_doctype"])
        bootinfo.dsc_supported_doctypes = [d.ref_doctype for d in format_settings]
    except Exception:
        bootinfo.dsc_supported_doctypes = []
