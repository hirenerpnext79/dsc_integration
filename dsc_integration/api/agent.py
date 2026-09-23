import hashlib
import secrets
from datetime import timezone as _timezone
import json
import frappe
from frappe.utils import now_datetime

_PAIRING_KEY_PREFIX = "e_sign:pairing:"
_PAIRING_TTL_SECONDS = 600  # 10 minutes

def _pairing_key(code):
	return _PAIRING_KEY_PREFIX + code

def _hash_token(token):
	return hashlib.sha256(token.encode("utf-8")).hexdigest()

@frappe.whitelist()
def generate_pairing_code():
	def _public_site_url():
		req = getattr(frappe.local, "request", None)
		if req is not None:
			xfh = req.headers.get("X-Forwarded-Host") or req.headers.get("X-Original-Host")
			host = xfh or req.host
			proto = req.headers.get("X-Forwarded-Proto") or ("https" if req.is_secure else "http")
			if host:
				return f"{proto}://{host}"
		return frappe.utils.get_url()

	site_url = _public_site_url()
	code = secrets.token_urlsafe(16)
	payload = {
		"user": frappe.session.user,
		"created_at": str(now_datetime()),
		"site_url": site_url,
	}

	frappe.cache().set_value(
		_pairing_key(code),
		json.dumps(payload),
		expires_in_sec=_PAIRING_TTL_SECONDS,
	)

	return {
		"pairing_code": code,
		"expires_in_seconds": _PAIRING_TTL_SECONDS,
		"site_url": site_url,
	}

@frappe.whitelist(allow_guest=True)
def validate_pairing_code(pairing_code, agent_fingerprint, os_platform=None, agent_version=None):
	key = _pairing_key(pairing_code)
	raw = frappe.cache().get_value(key)
	if not raw:
		frappe.throw("Invalid or expired pairing code.", frappe.AuthenticationError)

	frappe.cache().delete_value(key)

	if isinstance(raw, bytes):
		raw = raw.decode("utf-8")
	code_data = json.loads(raw)

	site_token = secrets.token_urlsafe(32)
	site_token_hash = _hash_token(site_token)

	agent_reg = frappe.get_doc({
		"doctype": "DSC Registration",
		"user": code_data["user"],
		"agent_fingerprint": agent_fingerprint,
		"display_name": f"{os_platform or 'Unknown'} Agent",
		"paired_on": now_datetime(),
		"last_seen_on": now_datetime(),
		"is_active": 1,
		"os_platform": os_platform,
		"agent_version": agent_version,
		"site_token_hash": site_token_hash,
	})

	agent_reg.insert(ignore_permissions=True)
	frappe.db.commit()

	return {
		"status": "paired",
		"site_token": site_token,
		"site_url": code_data["site_url"],
		"agent_registration": agent_reg.name
	}

@frappe.whitelist(allow_guest=True)
def verify_site_token(site_token, agent_fingerprint=None):
	if not site_token:
		return None

	token_hash = _hash_token(site_token)
	filters = {"site_token_hash": token_hash, "is_active": 1}
	if agent_fingerprint:
		filters["agent_fingerprint"] = agent_fingerprint

	agent_name = frappe.db.get_value("DSC Registration", filters, "name")
	if not agent_name:
		return None

	frappe.db.set_value("DSC Registration", agent_name, "last_seen_on", now_datetime())
	return agent_name