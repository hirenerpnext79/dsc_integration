import frappe
from frappe import _

@frappe.whitelist()
def is_dsc_required(doctype=None):
    current_user = frappe.session.user
    if current_user == 'Administrator':
        return False
        
    if not doctype:
        return False
        
    settings_name = frappe.db.get_value('HNS Approval Settings', {'ref_doctype': doctype}, 'name')
    if not settings_name:
        return False
        
    user_row = frappe.db.get_value(
        "HNS Approval User",
        {"parent": settings_name, "parenttype": "HNS Approval Settings", "user": current_user},
        ["name", "dsc_allowed"],
        as_dict=True
    )
    
    if not user_row:
        frappe.throw(_('You are not authorized to perform workflow approval.'))
            
    return bool(user_row.dsc_allowed)

@frappe.whitelist()
def verify_workflow_certificate(fingerprint, doctype=None, docname=None):
    current_user = frappe.session.user
    if not fingerprint:
        return {'status': False, 'msg': 'Missing DSC Certificate fingerprint.'}
        
    fingerprint = fingerprint.upper()
    
    if not doctype:
        return {'status': False, 'msg': 'Missing DocType.'}
        
    settings_name = frappe.db.get_value('HNS Approval Settings', {'ref_doctype': doctype}, 'name')
    if not settings_name:
        return {'status': False, 'msg': 'No Approval Settings found for this DocType.'}
        
    dsc_allowed_ref = frappe.db.get_value(
        "HNS Approval User",
        {"parent": settings_name, "parenttype": "HNS Approval Settings", "user": current_user},
        "dsc_allowed"
    )
    
    if not dsc_allowed_ref:
        return {'status': False, 'msg': 'You are not authorized for workflow approval with DSC.'}
        
    assigned_fingerprint = frappe.db.get_value('DSC Certificate', dsc_allowed_ref, 'certificate_fingerprint')
    
    if assigned_fingerprint and assigned_fingerprint.upper() == fingerprint:
        allowed_users = frappe.db.get_all('DSC Certificate Users', filters={'parent': dsc_allowed_ref, 'parenttype': 'DSC Certificate'}, pluck='user')
        if allowed_users and current_user not in allowed_users:
            return {'status': False, 'msg': 'You are not authorized to use this specific DSC Certificate.'}
        
        cert_name = frappe.db.get_value("DSC Certificate", {"certificate_fingerprint": fingerprint}, "name")
        from dsc_integration.utils.logger import log_dsc_action
        log_dsc_action(mode="Approval", certificate=cert_name, reference_doctype=doctype, doc_id=docname)
        
        return {'status': True}
        
    return {'status': False, 'msg': 'This DSC Certificate is not assigned to you for approval.'}
