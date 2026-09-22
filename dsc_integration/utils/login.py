import frappe
from frappe import _

def _resolve_user(usr):
    if not usr:
        return None
    user_email = frappe.db.get_value("User", {"email": usr}, "name")
    if not user_email:
        user_email = frappe.db.get_value("User", {"username": usr}, "name")
    if not user_email:
        user_email = frappe.db.get_value("User", {"mobile_no": usr}, "name")
    return user_email or usr

@frappe.whitelist(allow_guest=True)
def is_dsc_required(usr, mac_address=None):
    if not usr:
        return False
        
    user_email = _resolve_user(usr)
    
    if not mac_address and frappe.request:
        mac_address = frappe.request.headers.get("X-MAC-Address")
        
    if not mac_address:
        return False
        
    device_maps = frappe.get_all(
        "HNS Device Map",
        filters={"mac_address": mac_address},
        fields=["name", "dsc_required"]
    )

    if not device_maps:
        return False
        
    device_map = frappe.get_doc("HNS Device Map", device_maps[0].name)
    
    # Fast path: If the device map does not require DSC, we can return immediately
    if not device_map.dsc_required:
        return False
        
    user_allowed = False
    
    # Check if user explicitly allowed
    for row in device_map.allowed_user:
        user_val = row.user if hasattr(row, "user") else (row.dsc_allowed_user if hasattr(row, "dsc_allowed_user") else None)
        if user_val == user_email:
            user_allowed = True
            break
            
    # Check if role allowed
    if not user_allowed and user_email:
        user_roles = frappe.get_roles(user_email)
        for row in device_map.dsc_allowed_role:
            role_val = row.role if hasattr(row, "role") else (row.dsc_allowed_role if hasattr(row, "dsc_allowed_role") else None)
            if role_val in user_roles:
                user_allowed = True
                break
                
    if user_allowed:
        return True
        
    return False

def check_mac_before_login():
    try:
        # Only run this logic if the user is trying to log in
        if not frappe.request:
            return
            
        is_login_request = (
            frappe.form_dict.get("cmd") == "login" or
            (frappe.request.path in ["/", "/login", "/api/method/login"] and frappe.request.method == "POST" and "pwd" in frappe.form_dict)
        )
        
        if not is_login_request:
            return
            
        user_login_id = frappe.form_dict.get("usr")
        mac_address = frappe.form_dict.get("mac_address") or frappe.request.headers.get("X-MAC-Address")
        
        if is_dsc_required(user_login_id, mac_address):
            is_dsc_login = frappe.form_dict.get("is_dsc_login") or frappe.flags.get("is_dsc_login")
            
            if not is_dsc_login:
                frappe.throw(_("DSC Login is required for this device before proceeding."))
                
            dsc_fingerprint = frappe.form_dict.get("dsc_fingerprint")
            if not dsc_fingerprint:
                frappe.throw(_("Missing DSC Certificate fingerprint."))
                
            # Reuse the validation logic
            verify_result = verify_certificate_mapping(user_email, dsc_fingerprint)
            if not verify_result or not verify_result.get("status"):
                error_msg = verify_result.get("msg") if verify_result else "Invalid DSC Certificate."
                frappe.throw(_(error_msg))
                
    except Exception as e:
        frappe.log_error(title="DSC Device Check Error", message=frappe.get_traceback())
        raise e

@frappe.whitelist(allow_guest=True)
def verify_certificate_mapping(usr, fingerprint):
    if not usr or not fingerprint:
        return False
        
    user_email = _resolve_user(usr)
        
    registered_cert = frappe.db.exists("DSC Certificate", {"certificate_fingerprint": fingerprint})
    if not registered_cert:
        return {"status": False, "msg": "This DSC Certificate is not registered in the system."}
        
    is_user_mapped = frappe.db.exists("DSC Certificate Users", {"parent": registered_cert, "user": user_email})
    if not is_user_mapped:
        return {"status": False, "msg": "This DSC Certificate is not registered to your account."}
        
    return {"status": True}
