# Copyright (c) 2026, HNS and contributors
# For license information, please see license.txt

import os
import json
import base64
import secrets

import frappe
from frappe.model.document import Document
from frappe.utils import now_datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class DSCUserCertificate(Document):
	pass


@frappe.whitelist()
def extract_certificate_from_der(cert_der_b64):
	cert_der = base64.b64decode(cert_der_b64)
	cert = x509.load_der_x509_certificate(cert_der, default_backend())

	holder_name = cert.subject.rfc4514_string()
	try:
		holder_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
	except Exception:
		pass
		
	issuer = cert.issuer.rfc4514_string()
	try:
		issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
	except Exception:
		pass
		
	serial_number = str(cert.serial_number)
	valid_from = cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")
	valid_until = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")
	fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()

	full_details = {
		"version": cert.version.name if cert.version else None,
		"serial_number": serial_number,
		"fingerprint_sha256": fingerprint,
		"not_valid_before": cert.not_valid_before_utc.isoformat(),
		"not_valid_after": cert.not_valid_after_utc.isoformat(),
		"issuer_full_dn": cert.issuer.rfc4514_string(),
		"subject_full_dn": cert.subject.rfc4514_string(),
		"signature_algorithm_oid": cert.signature_algorithm_oid._name,
		"public_key_type": cert.public_key().__class__.__name__,
		"extensions": {}
	}

	for ext in cert.extensions:
		try:
			ext_name = ext.oid._name if ext.oid._name else ext.oid.dotted_string
			full_details["extensions"][ext_name] = str(ext.value)
		except Exception:
			pass

	return {
		"holder_name": holder_name,
		"certificate_serial": serial_number,
		"issuer": issuer,
		"valid_from": valid_from,
		"valid_until": valid_until,
		"certificate_fingerprint": fingerprint,
		"certificate_details": json.dumps(full_details, indent=2)
	}


_PAIRING_TTL_SECONDS = 600

def _pairing_key(code):
	return f"dsc_pair_{code}"


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
