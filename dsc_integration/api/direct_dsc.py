import frappe
import os
import asyncio
import io
import base64
import hashlib
import hmac
import secrets
import time

try:
    from asn1crypto import x509, algos, cms, core
    from pyhanko.sign import signers, fields
    from pyhanko_certvalidator.registry import SimpleCertificateStore
    from pyhanko.pdf_utils.writer import copy_into_new_writer
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.stamp import TextStampStyle
    from pyhanko.sign.signers.pdf_byterange import PreparedByteRangeDigest
    PYHANKO_AVAILABLE = True
except ImportError:
    PYHANKO_AVAILABLE = False


def get_stamp_settings(doctype, print_format, agent_settings):
    settings = {
        "stamp_x": agent_settings.get("stamp_x") or 10,
        "stamp_y": agent_settings.get("stamp_y") or 10,
        "stamp_width": agent_settings.get("stamp_width") or 200,
        "stamp_height": agent_settings.get("stamp_height") or 60,
        "stamp_page": agent_settings.get("stamp_page"),
        "stamp_text": agent_settings.get("stamp_text") or "Digitally signed by %(signer)s\nDate: %(ts)s"
    }
    
    format_setting_name = frappe.db.get_value("DSC Format Setting", {"ref_doctype": doctype}, "name")
    if not format_setting_name:
        return settings
        
    doc = frappe.get_doc("DSC Format Setting", format_setting_name)
    
    for row in doc.format_settings:
        if row.print_format == print_format:
            if row.stamp_x: settings["stamp_x"] = row.stamp_x
            if row.stamp_y: settings["stamp_y"] = row.stamp_y
            if row.stamp_width: settings["stamp_width"] = row.stamp_width
            if row.stamp_height: settings["stamp_height"] = row.stamp_height
            if row.stamp_page: settings["stamp_page"] = row.stamp_page
            if row.stamp_text: settings["stamp_text"] = row.stamp_text
            return settings
            
    if doc.stamp_x: settings["stamp_x"] = doc.stamp_x
    if doc.stamp_y: settings["stamp_y"] = doc.stamp_y
    if doc.stamp_width: settings["stamp_width"] = doc.stamp_width
    if doc.stamp_height: settings["stamp_height"] = doc.stamp_height
    if doc.stamp_page: settings["stamp_page"] = doc.stamp_page
    if doc.stamp_text: settings["stamp_text"] = doc.stamp_text
    
    return settings

@frappe.whitelist()
def verify_direct_certificate(fingerprint, doctype=None, docname=None):
    current_user = frappe.session.user
    if current_user == 'Administrator':
        return {'status': True}
        
    if not fingerprint:
        return {'status': False, 'msg': 'Missing DSC Certificate fingerprint.'}
        
    fingerprint = fingerprint.upper()
    
    if not doctype:
        return {'status': False, 'msg': 'Missing DocType.'}
        
    settings_name = frappe.db.get_value('DSC Format Setting', {'ref_doctype': doctype, 'is_active': 1}, 'name')
    if not settings_name:
        return {'status': True}
        
    user_row = frappe.db.get_value(
        "HNS Approval User",
        {"parent": settings_name, "parenttype": "DSC Format Setting", "user": current_user},
        ["name", "dsc_allowed"],
        as_dict=True
    )
    
    if user_row:
        dsc_allowed_ref = user_row.dsc_allowed
        if not dsc_allowed_ref:
            return {'status': True}
            
        assigned_fingerprint = frappe.db.get_value('DSC Certificate', dsc_allowed_ref, 'certificate_fingerprint')
        
        if assigned_fingerprint and assigned_fingerprint.upper() == fingerprint:
            allowed_users = frappe.db.get_all('DSC Certificate Users', filters={'parent': dsc_allowed_ref, 'parenttype': 'DSC Certificate'}, pluck='user')
            if allowed_users and current_user not in allowed_users:
                return {'status': False, 'msg': 'You are not authorized to use this specific DSC Certificate.'}
            return {'status': True}
            
        return {'status': False, 'msg': 'This DSC Certificate is not assigned to you.'}
        
    parent_dsc_allowed = frappe.db.get_all("DSC Allowed", filters={"parent": settings_name, "parenttype": "DSC Format Setting"}, pluck="dsc_allowed")
    
    if not parent_dsc_allowed:
        return {'status': True}
        
    for cert_name in parent_dsc_allowed:
        assigned_fingerprint = frappe.db.get_value('DSC Certificate', cert_name, 'certificate_fingerprint')
        if assigned_fingerprint and assigned_fingerprint.upper() == fingerprint:
            allowed_users = frappe.db.get_all('DSC Certificate Users', filters={'parent': cert_name, 'parenttype': 'DSC Certificate'}, pluck='user')
            if allowed_users and current_user not in allowed_users:
                return {'status': False, 'msg': 'You are not authorized to use this specific DSC Certificate.'}
            return {'status': True}
            
    return {'status': False, 'msg': 'This DSC Certificate is not authorized for this DocType.'}

@frappe.whitelist()
def initiate_direct_sign(doctype, docname, print_format, cert_der_b64):
    if not PYHANKO_AVAILABLE:
        frappe.throw("pyHanko is not installed")
        
    from frappe.utils.pdf import get_pdf
    
    # Fetch Settings once
    settings = frappe.get_single("DSC Agent Settings")
    
    # HMAC Generation early check
    try:
        hmac_secret = settings.get_password("hmac_secret", raise_exception=False)
    except Exception:
        hmac_secret = None
        
    if not hmac_secret:
        frappe.throw("HMAC Secret is not configured in DSC Agent Settings. Please configure it to continue signing.")
        
    cert_der = base64.b64decode(cert_der_b64)
    cert = x509.Certificate.load(cert_der)
    
    frappe.local.response.filename = f"{docname}.pdf"
    html = frappe.get_print(doctype, docname, print_format, as_pdf=False)
    pdf_bytes = get_pdf(html)
    
    pdf_stream = io.BytesIO(pdf_bytes)
    reader = PdfFileReader(pdf_stream)
    writer = copy_into_new_writer(reader)
    
    # Stamp Settings
    stamp_settings = get_stamp_settings(doctype, print_format, settings)
    stamp_x = int(stamp_settings.get("stamp_x") or 10)
    stamp_y = int(stamp_settings.get("stamp_y") or 10)
    stamp_width = int(stamp_settings.get("stamp_width") or 200)
    stamp_height = int(stamp_settings.get("stamp_height") or 60)
    stamp_page = stamp_settings.get("stamp_page")
    stamp_text = stamp_settings.get("stamp_text") or "Digitally signed by %(signer)s\nDate: %(ts)s"

    try:
        total_pages = int(reader.root['/Pages']['/Count'])
    except Exception:
        total_pages = 1
        
    on_page = max(0, total_pages - 1) if stamp_page == "Last Page" else 0
        
    sig_field = fields.SigFieldSpec(
        'Signature1', 
        on_page=on_page, 
        box=(stamp_x, stamp_y, stamp_x + stamp_width, stamp_y + stamp_height)
    )
    fields.append_signature_field(writer, sig_field)
    
    signer = signers.ExternalSigner(
        signing_cert=cert,
        cert_registry=SimpleCertificateStore(),
        signature_mechanism=algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'}),
        signature_value=b'\x00' * 512
    )
    
    out_stream = io.BytesIO()
    
    try:
        use_custom_watermark = frappe.utils.cint(settings.get("use_custom_watermark"))
        doc_url = frappe.utils.get_url(f"/app/{doctype}/{docname}")

        from pyhanko.pdf_utils.images import PdfImage
        
        border_width = int(settings.get("border_width") or 1)
        bg_opacity = float(settings.get("background_opacity") or 0.4)
        watermark_path = settings.get("custom_watermark")
        
        background_img = None
        if use_custom_watermark and watermark_path:
            if watermark_path.startswith('/private/'):
                full_path = frappe.get_site_path(watermark_path.lstrip('/'))
            else:
                full_path = frappe.get_site_path('public', watermark_path.lstrip('/'))
            if os.path.exists(full_path):
                background_img = PdfImage(full_path)
            else:
                frappe.log_error("DSC Watermark Error", f"Watermark file not found at {full_path}")
        
        stamp_style = TextStampStyle(
            stamp_text=stamp_text, 
            border_width=border_width, 
            background_opacity=bg_opacity,
            background=background_img
        )
                
        sig_meta = signers.PdfSignatureMetadata(field_name='Signature1')
        pdf_signer = signers.PdfSigner(sig_meta, signer=signer, stamp_style=stamp_style)
    except Exception as e:
        frappe.log_error('DSC Stamp Error', str(e))
        sig_meta = signers.PdfSignatureMetadata(field_name='Signature1')
        pdf_signer = signers.PdfSigner(sig_meta, signer=signer)

    async def prepare():
        return await pdf_signer.async_digest_doc_for_signing(
            pdf_out=writer,
            output=out_stream,
            bytes_reserved=16384
        )
        
    prep_digest_obj, _tbs_doc, _ = asyncio.run(prepare())
    document_digest_bytes = prep_digest_obj.document_digest
    
    # CMS requires signing the SignedAttributes
    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
        cms.CMSAttribute({"type": "message_digest", "values": [core.OctetString(document_digest_bytes)]}),
    ])
    
    hash_to_sign_hex = hashlib.sha256(signed_attrs.dump()).hexdigest()
    hash_algorithm = "sha256"
    session_id = frappe.generate_hash(length=10)
    
    timestamp = int(time.time())
    nonce = secrets.token_hex(16)
    mac_payload = f"{session_id}|{hash_to_sign_hex}|{hash_algorithm}|{timestamp}|{nonce}".encode("utf-8")
    
    hmac_signature = hmac.new(hmac_secret.encode("utf-8"), mac_payload, hashlib.sha256).hexdigest()
    
    with open(f"/tmp/dsc_prep_{session_id}.pdf", "wb") as f:
        f.write(out_stream.getvalue())
        
    frappe.cache().set_value(
        f"dsc_prep_{session_id}", 
        {
            "cert_der_b64": cert_der_b64, 
            "doctype": doctype, 
            "docname": docname,
            "document_digest_hex": document_digest_bytes.hex(),
            "reserved_region_start": prep_digest_obj.reserved_region_start,
            "reserved_region_end": prep_digest_obj.reserved_region_end,
            "print_format": print_format,
        }, 
        expires_in_sec=600
    )
    
    return {
        "session_id": session_id, 
        "hash_to_sign": hash_to_sign_hex, 
        "hash_algorithm": hash_algorithm,
        "hmac_timestamp": timestamp,
        "hmac_nonce": nonce,
        "hmac_signature": hmac_signature
    }

@frappe.whitelist()
def finalize_direct_sign(session_id, signature_hex, doctype=None, docname=None, **kwargs):
    if not PYHANKO_AVAILABLE:
        frappe.throw("pyHanko is not installed")
        
    cached = frappe.cache().get_value(f"dsc_prep_{session_id}")
    if not cached or not os.path.exists(f"/tmp/dsc_prep_{session_id}.pdf"):
        frappe.throw("Signing session expired or invalid.")
        
    with open(f"/tmp/dsc_prep_{session_id}.pdf", "rb") as f:
        pdf_bytes = f.read()
        
    try:
        signature_bytes = bytes.fromhex(signature_hex)
    except ValueError:
        signature_bytes = base64.b64decode(signature_hex)
        
    cert_der = base64.b64decode(cached["cert_der_b64"])
    cert = x509.Certificate.load(cert_der)
    
    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
        cms.CMSAttribute({
            "type": "message_digest",
            "values": [core.OctetString(bytes.fromhex(cached["document_digest_hex"]))],
        }),
    ])
    
    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": cert.issuer,
                "serial_number": cert.serial_number,
            })
        }),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": signed_attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
        "signature": signature_bytes,
    })

    signed_data = cms.SignedData({
        "version": "v1",
        "digest_algorithms": cms.DigestAlgorithms([algos.DigestAlgorithm({"algorithm": "sha256"})]),
        "encap_content_info": cms.ContentInfo({"content_type": "data"}),
        "certificates": cms.CertificateSet([cms.CertificateChoices({"certificate": cert})]),
        "signer_infos": cms.SignerInfos([signer_info]),
    })

    cms_bytes = cms.ContentInfo({"content_type": "signed_data", "content": signed_data}).dump()
    
    prep_digest_obj = PreparedByteRangeDigest(
        document_digest=bytes.fromhex(cached["document_digest_hex"]),
        reserved_region_start=cached["reserved_region_start"],
        reserved_region_end=cached["reserved_region_end"],
    )
    
    output = io.BytesIO(pdf_bytes)
    from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
    import asyncio
    
    # We must use async_finish_signing instead of fill_with_cms to ensure
    # all background image XObjects and cross-references are properly finalized
    # in the PDF stream according to pyHanko docs.
    asyncio.run(PdfTBSDocument.async_finish_signing(
        output, prep_digest_obj, cms_bytes
    ))
    
    file_doc = frappe.new_doc("File")
    file_doc.file_name = f"{cached['docname']}_DSC_Signed.pdf"
    file_doc.is_private = 1
    file_doc.content = output.getvalue()
    file_doc.attached_to_doctype = cached["doctype"]
    file_doc.attached_to_name = cached["docname"]
    file_doc.save(ignore_permissions=True)
    
    frappe.cache().delete_value(f"dsc_prep_{session_id}")
    
    cert_name = frappe.db.get_value("DSC Certificate", {"certificate_fingerprint": cert.sha256.hex().upper()}, "name")
    from dsc_integration.utils.logger import log_dsc_action
    log_dsc_action(mode="Signature", certificate=cert_name, reference_doctype=cached.get("doctype"), doc_id=cached.get("docname"), pdf_format=cached.get("print_format"), pdf_file_link=file_doc.file_url)
    
    return {"status": "success"}
