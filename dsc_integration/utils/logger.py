import frappe
from frappe.utils import nowdate, nowtime

def log_dsc_action(mode, certificate=None, reference_doctype=None, doc_id=None, pdf_format=None, pdf_file_link=None):
    try:
        if not frappe.db.exists('DocType', 'HNS DSC Log'):
            return

        mac_address = frappe.request.headers.get('X-MAC-Address') if getattr(frappe, "request", None) else None
        
        import requests
        ip_address = None
        try:
            ip_address = requests.get('https://api.ipify.org', timeout=3).text
        except Exception:
            if getattr(frappe, "request", None):
                ip_address = frappe.request.remote_addr

        person_name = None
        device_name = None
        os_name = None
        device_type = None
        dsc_required = None
        device_id = None
        
        if mac_address:
            device_map = frappe.db.get_value(
                'HNS Device Map', 
                {'mac_address': mac_address}, 
                ['name', 'person_name', 'device_name', 'os', 'device_type', 'dsc_required'],
                as_dict=True
            )
            if device_map:
                person_name = device_map.person_name
                device_name = device_map.device_name
                os_name = device_map.os
                device_type = device_map.device_type
                dsc_required = device_map.dsc_required
                device_id = device_map.name

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
            'pdf_format': pdf_format if mode == 'Signature' else None,
            'pdf_file_link': pdf_file_link if mode == 'Signature' else None,
            'person_name': person_name,
            'device_name': device_name,
            'os': os_name,
            'device_type': device_type,
            'dsc_required': dsc_required,
            'device_id': device_id
        })
        doc.insert(ignore_permissions=True)
        frappe.db.commit()
    except Exception as e:
        frappe.log_error('DSC Logging Error', str(e))
