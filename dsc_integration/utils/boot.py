import frappe

def extend_bootinfo(bootinfo):
    try:
        settings = frappe.get_doc('DSC Agent Settings')
        if settings.get('supported_doctypes'):
            bootinfo.dsc_supported_doctypes = [d.document_type for d in settings.supported_doctypes]
        else:
            bootinfo.dsc_supported_doctypes = []
    except Exception:
        bootinfo.dsc_supported_doctypes = []
