import frappe
from frappe.utils import nowdate, nowtime

def log_dsc_action(mode, certificate=None, reference_doctype=None, doc_id=None):
    try:
        if not frappe.db.exists('DocType', 'HNS DSC Log'):
            return

        mac_address = frappe.request.headers.get('X-MAC-Address') if getattr(frappe, "request", None) else None
        
        ip_address = None
        if hasattr(frappe.local, "request_ip"):
            ip_address = frappe.local.request_ip

        doc = frappe.get_doc({
            'doctype': 'HNS DSC Log',
            'mode': mode,
            'certificate': certificate,
            'user': frappe.session.user if frappe.session else None,
            'date': nowdate(),
            'time': nowtime(),
            'reference_doctype': reference_doctype,
            'doc_id': doc_id,
            'mac_address': mac_address,
            'ip_address': ip_address,
            
        })
        doc.insert(ignore_permissions=True)
        frappe.db.commit()
    except Exception as e:
        frappe.log_error('DSC Logging Error', str(e))
