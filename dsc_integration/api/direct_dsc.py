import frappe
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
    stamp_x = int(settings.get("stamp_x") or 10)
    stamp_y = int(settings.get("stamp_y") or 10)
    stamp_width = int(settings.get("stamp_width") or 200)
    stamp_height = int(settings.get("stamp_height") or 60)
    stamp_page = settings.get("stamp_page")
    stamp_text = settings.get("stamp_text") or "Digitally signed by %(signer)s\nDate: %(ts)s"

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
        stamp_style = TextStampStyle(stamp_text=stamp_text, border_width=1)
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
            bytes_reserved=8192
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
    
    frappe.cache().set_value(
        f"dsc_prep_{session_id}", 
        {
            "pdf_bytes": out_stream.getvalue(), 
            "cert_der_b64": cert_der_b64, 
            "doctype": doctype, 
            "docname": docname,
            "document_digest_hex": document_digest_bytes.hex(),
            "reserved_region_start": prep_digest_obj.reserved_region_start,
            "reserved_region_end": prep_digest_obj.reserved_region_end,
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
    if not cached:
        frappe.throw("Signing session expired or invalid.")
        
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
    
    output = io.BytesIO(cached["pdf_bytes"])
    prep_digest_obj.fill_with_cms(output, cms_bytes)
    
    file_doc = frappe.new_doc("File")
    file_doc.file_name = f"{cached['docname']}_DSC_Signed.pdf"
    file_doc.is_private = 1
    file_doc.content = output.getvalue()
    file_doc.attached_to_doctype = cached["doctype"]
    file_doc.attached_to_name = cached["docname"]
    file_doc.save(ignore_permissions=True)
    
    frappe.cache().delete_value(f"dsc_prep_{session_id}")
    return {"status": "success"}
