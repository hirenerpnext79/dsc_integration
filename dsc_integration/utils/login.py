import frappe
from frappe import _

def get_current_mac_address(provided_mac=None):
    device_info = {}
    if provided_mac:
        device_info = {"mac_address": provided_mac}
    else:
        mac_address = None
        if frappe.form_dict:
            mac_address = frappe.form_dict.get("mac_address")
        if not mac_address and frappe.request:
            mac_address = frappe.request.headers.get("X-MAC-Address")
            
        if mac_address:
            device_info = {"mac_address": mac_address}
        else:
            try:
                from dsc_integration.dsc_integration.doctype.hns_device_map.hns_device_map import get_physical_mac
                fallback = get_physical_mac()
                if fallback:
                    device_info = fallback # Returns dict with mac_address, device_name, person_name
            except Exception:
                pass

    if not device_info:
        return None

    mac_address = device_info.get("mac_address")
    auto_create_device_map(mac_address, device_info)
    return mac_address

def auto_create_device_map(mac_address, device_info):
    if not mac_address or frappe.db.exists("HNS Device Map", mac_address):
        return
        
    try:
        user = None
        if frappe.form_dict:
            user = frappe.form_dict.get("usr")
        if not user and frappe.session:
            user = frappe.session.user
            
        new_device = frappe.new_doc("HNS Device Map")
        new_device.mac_address = mac_address
        
        if device_info.get("device_name"):
            new_device.device_name = device_info.get("device_name")
            
        person_name = device_info.get("person_name")
        new_device.person_name = person_name if person_name else f"{user or 'Unknown'}"
        
        new_device.insert(ignore_permissions=True)
        frappe.db.commit()
    except Exception as e:
        frappe.log_error("Auto Create Device Map Error", str(e))

def _resolve_user(usr):
    if not usr:
        return None
    user = frappe.db.get_value("User", {"email": usr}, "name")
    if not user:
        user = frappe.db.get_value("User", {"username": usr}, "name")
    if not user:
        user = frappe.db.get_value("User", {"mobile_no": usr}, "name")
    return user or usr

def is_admin(user):
    return user == "Administrator"

def check_device_access(user, mac_address=None):
    if is_admin(user):
        return True

    mac_address = get_current_mac_address(mac_address)
        
    if not mac_address:
        return True
        
    device_map = frappe.get_doc("HNS Device Map", mac_address)

    if not device_map:
        return True

    if device_map.disable:
        frappe.throw(frappe._("This PC is disabled and cannot be accessed by any user."))
        
    return check_user_or_role_access(mac_address, user, device_map)

@frappe.whitelist(allow_guest=True)
def check_device_access_api(usr):
    user = _resolve_user(usr)
    
    if is_admin(user):
        return True
        
    if not check_device_access(user):
        frappe.throw(_("You are not authorized to use this device."))
    return True

@frappe.whitelist(allow_guest=True)
def is_dsc_required(usr, mac_address=None):
    user = _resolve_user(usr)
    
    if is_admin(user) or not user:
        return False
    
    mac_address = get_current_mac_address(mac_address)
    
    if mac_address:
        dsc_req = frappe.db.get_value("HNS Device Map", mac_address, "dsc_required")

        if dsc_req:
            has_dsc_allowed = frappe.db.exists("DSC Allowed", {"parent": mac_address, "parentfield": "dsc_allowed", "parenttype": "HNS Device Map"})

            if has_dsc_allowed:                
                return check_user_or_role_access(mac_address, user)
                
            return False
            
    return False

def check_mac_before_login():
    try:
        if not frappe.request:
            return
            
        is_login_request = (
            frappe.form_dict.get("cmd") == "login" or
            (frappe.request.path in ["/", "/login", "/api/method/login"] and frappe.request.method == "POST" and "pwd" in frappe.form_dict)
        )
        
        if not is_login_request:
            return
            
        user = frappe.form_dict.get("usr")
        mac_address = get_current_mac_address()
        user = _resolve_user(user)

        if is_dsc_required(user, mac_address):
            is_dsc_login = frappe.form_dict.get("is_dsc_login") or frappe.flags.get("is_dsc_login")
            
            if not is_dsc_login:
                frappe.throw(_("DSC Login is required for this device before proceeding."))
                
            dsc_fingerprint = frappe.form_dict.get("dsc_fingerprint")
            if not dsc_fingerprint:
                frappe.throw(_("Missing DSC Certificate fingerprint."))
                
            verify_result = verify_certificate_mapping(user, dsc_fingerprint)
            if not verify_result or not verify_result.get("status"):
                error_msg = verify_result.get("msg") if verify_result else "Invalid DSC Certificate."
                frappe.throw(_(error_msg))
            
            cert_name = frappe.db.get_value("DSC Certificate", {"certificate_fingerprint": dsc_fingerprint}, "name") if dsc_fingerprint else None
            from dsc_integration.utils.logger import log_dsc_action
            log_dsc_action(mode="Login", certificate=cert_name)  
    except Exception as e:
        frappe.log_error(title="DSC Device Check Error", message=frappe.get_traceback())
        raise e

def check_user_or_role_access(mac_address, user, device_map=None):
    if not device_map:
        device_map = frappe.get_cached_doc("HNS Device Map", mac_address)
        
    has_user = bool(device_map.allowed_user)
    has_role = bool(device_map.dsc_allowed_role)
    
    if not has_user and not has_role:
        return True
        
    user_match = has_user and any(row.user == user for row in device_map.allowed_user)
    role_match = has_role and any(row.role in frappe.get_roles(user) for row in device_map.dsc_allowed_role)
    return user_match or role_match

def _check_cert_allowed(device_map, fingerprint, user):
    if not device_map.dsc_allowed:
        return False, "You do not have permission to use DSC on this device."
        
    cert_names = [row.dsc_allowed for row in device_map.dsc_allowed]
    
    matching_cert = frappe.db.get_value("DSC Certificate", 
        {"name": ("in", cert_names), "certificate_fingerprint": fingerprint},
        "name"
    )
    
    if not matching_cert:
        return False, "You do not have permission to use DSC on this device."
        
    is_allowed = frappe.db.exists("DSC Certificate Users", 
        {"parent": matching_cert, "parenttype": "DSC Certificate", "user": user}
    )
    
    if not is_allowed:
        return False, "You are not authorized to use this specific DSC Certificate."
        
    return True, ""

@frappe.whitelist(allow_guest=True)
def verify_certificate_mapping(usr, fingerprint):
    fingerprint = fingerprint.upper()
    if not usr or not fingerprint:
        return {"status": False, "msg": _("User and Fingerprint are required")}
        
    user = _resolve_user(usr)
    mac_address = get_current_mac_address()

    if mac_address:
        dsc_required = frappe.db.get_value("HNS Device Map", mac_address, "dsc_required")
        
        if dsc_required:
            device_map = frappe.get_cached_doc("HNS Device Map", mac_address)
            is_allowed = check_user_or_role_access(mac_address, user, device_map)

            if not is_allowed:
                has_user = bool(device_map.allowed_user)
                has_role = bool(device_map.dsc_allowed_role)
                if has_user and not has_role:
                    return {"status": False, "msg": _("You are not authorized to use DSC on this device (User not in allowed list).")}
                elif has_role and not has_user:
                    return {"status": False, "msg": _("You are not authorized to use DSC on this device (Role not in allowed list).")}
                else:
                    return {"status": False, "msg": _("You are not authorized to use DSC on this device (User and Role not in allowed list).")}

            if device_map.dsc_allowed:
                cert_match, cert_msg = _check_cert_allowed(device_map, fingerprint, user)
                is_allowed = is_allowed and cert_match
                if not cert_match:
                    return {"status": False, "msg": _(cert_msg)}
                            
                if not is_allowed:
                    return {"status": False, "msg": "You do not have permission to use DSC on this device."}
        
    return {"status": True}