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
    user_email = _resolve_user(usr)
    
    if not mac_address and frappe.request:
        mac_address = frappe.request.headers.get("X-MAC-Address")
        
    # Check if the specific device requires it
    if mac_address:
        dsc_req = frappe.db.get_value("HNS Device Map", {"mac_address": mac_address}, "dsc_required")
        if dsc_req:
            return True

    # If the user hasn't provided a valid ID yet, we can't check
    if not user_email:
        return False

    # Check if the user or their role is restricted by ANY HNS Device Map with DSC Required
    user_roles = frappe.get_roles(user_email)
    
    device_maps = frappe.get_all("HNS Device Map", filters={"dsc_required": 1}, pluck="name")
    if not device_maps:
        return False
        
    # Check if user is directly allowed in any of the required device maps
    if frappe.db.exists("DSC Allowed User", {"parent": ("in", device_maps), "parenttype": "HNS Device Map", "user": user_email}):
        return True
        
    # Check if user has a role allowed in any of the required device maps
    if user_roles and frappe.db.exists("DSC Allowed Role", {"parent": ("in", device_maps), "parenttype": "HNS Device Map", "role": ("in", user_roles)}):
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
                
            user_email = _resolve_user(user_login_id)
            verify_result = verify_certificate_mapping(user_email, dsc_fingerprint)
            if not verify_result or not verify_result.get("status"):
                error_msg = verify_result.get("msg") if verify_result else "Invalid DSC Certificate."
                frappe.throw(_(error_msg))
                
    except Exception as e:
        frappe.log_error(title="DSC Device Check Error", message=frappe.get_traceback())
        raise e

def _check_user_allowed(device_map, user_email):
    for row in device_map.allowed_user:
        if row.user == user_email:
            return True
    return False

def _check_role_allowed(device_map, user_email):
    user_roles = frappe.get_roles(user_email)
    for row in device_map.dsc_allowed_role:
        if row.role in user_roles:
            return True
    return False

def _check_cert_allowed(device_map, fingerprint):
    for row in device_map.dsc_allowed:
        assigned_fingerprint = frappe.db.get_value("DSC Certificate", row.dsc_allowed, "certificate_fingerprint")
        if assigned_fingerprint == fingerprint:
            return True
    return False

@frappe.whitelist(allow_guest=True)
def verify_certificate_mapping(usr, fingerprint):
    fingerprint = fingerprint.upper()
    if not usr or not fingerprint:
        return False
        
    user_email = _resolve_user(usr)
        
    # Check device restrictions if applicable
    mac_address = frappe.request.headers.get("X-MAC-Address") if frappe.request else None
    if mac_address:
        device_maps = frappe.get_all("HNS Device Map", filters={"mac_address": mac_address}, fields=["name", "dsc_required"])
        if device_maps:
            device_map = frappe.get_doc("HNS Device Map", device_maps[0].name)
            
            if device_map.dsc_required:
                has_restrictions = (bool(device_map.allowed_user) or bool(device_map.dsc_allowed_role)) and bool(device_map.dsc_allowed)
                
                if has_restrictions:
                    user_role_match = False
                    
                    if device_map.allowed_user:
                        user_role_match = _check_user_allowed(device_map, user_email)
                                
                    if not user_role_match and device_map.dsc_allowed_role:
                        user_role_match = _check_role_allowed(device_map, user_email)
                                
                    is_allowed = user_role_match

                    if device_map.dsc_allowed:
                        cert_match = _check_cert_allowed(device_map, fingerprint)
                        is_allowed = is_allowed and cert_match
                                
                    if not is_allowed:
                        return {"status": False, "msg": "You do not have permission to use DSC on this device."}
        
    return {"status": True}
