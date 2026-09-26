# Copyright (c) 2026, HNS and contributors
# For license information, please see license.txt

import frappe
import secrets
from frappe.model.document import Document


class DSCAgentSettings(Document):
	pass

def get_or_create_hmac_secret():
	doc = frappe.get_single("DSC Agent Settings")
	current = doc.get_password("hmac_secret", raise_exception=False) if doc.hmac_secret else None
	if current:
		return current

	new_secret = secrets.token_urlsafe(48)
	doc.hmac_secret = new_secret
	doc.save(ignore_permissions=True)
	frappe.db.commit()
	return new_secret