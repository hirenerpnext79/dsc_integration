import frappe
import asyncio

@frappe.whitelist()
def initiate_direct_sign(doctype, docname, print_format, cert_der_b64):
    from frappe.utils.pdf import get_pdf
    import io, base64
    from asn1crypto import x509, algos, cms, core
    import hashlib
    import hmac
    import secrets
    import time
    
    try:
        from pyhanko.sign import signers, fields
        from pyhanko_certvalidator.registry import SimpleCertificateStore
        from pyhanko.pdf_utils.writer import copy_into_new_writer
        from pyhanko.pdf_utils.reader import PdfFileReader
    except ImportError:
        frappe.throw("pyHanko is not installed")
        
    cert_der = base64.b64decode(cert_der_b64)
    cert = x509.Certificate.load(cert_der)
    
    frappe.local.response.filename = f"{docname}.pdf"
    html = frappe.get_print(doctype, docname, print_format, as_pdf=False)
    pdf_bytes = get_pdf(html)
    
    pdf_stream = io.BytesIO(pdf_bytes)
    reader = PdfFileReader(pdf_stream)
    writer = copy_into_new_writer(reader)
    
    sig_field = fields.SigFieldSpec('Signature1', box=(10, 10, 200, 60))
    fields.append_signature_field(writer, sig_field)
    
    signer = signers.ExternalSigner(
        signing_cert=cert,
        cert_registry=SimpleCertificateStore(),
        signature_mechanism=algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'}),
        signature_value=b'\x00' * 512
    )
    
    out_stream = io.BytesIO()
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
    
    # CMS requires signing the SignedAttributes, not the document hash directly
    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({
            "type": "content_type",
            "values": ["data"],
        }),
        cms.CMSAttribute({
            "type": "message_digest",
            "values": [core.OctetString(document_digest_bytes)],
        }),
    ])
    signed_attrs_der = signed_attrs.dump()
    hash_to_sign_hex = hashlib.sha256(signed_attrs_der).hexdigest()
    hash_algorithm = "sha256"
    
    session_id = frappe.generate_hash(length=10)
    
    # HMAC Generation
    try:
        hmac_secret = frappe.get_single("DSC Agent Settings").get_password("hmac_secret", raise_exception=False)
    except Exception:
        hmac_secret = None
    if not hmac_secret:
        hmac_secret = "REi9DpASSPZJTJ8hj61RNZFIacsgz1HPKCzne0e3c20hHBj9CUC37swxsgz3gsd_"
    timestamp = int(time.time())
    nonce = secrets.token_hex(16)
    mac_payload = "|".join([
        session_id,
        hash_to_sign_hex,
        hash_algorithm,
        str(timestamp),
        nonce,
    ]).encode("utf-8")
    
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
    import io, base64
    from asn1crypto import x509, cms, algos, core
    
    try:
        from pyhanko.sign.signers.pdf_byterange import PreparedByteRangeDigest
    except ImportError:
        pass
        
    cached = frappe.cache().get_value(f"dsc_prep_{session_id}")
    if not cached:
        frappe.throw("Signing session expired or invalid.")
        
    try:
        signature_bytes = bytes.fromhex(signature_hex)
    except ValueError:
        signature_bytes = base64.b64decode(signature_hex)
    cert_der = base64.b64decode(cached["cert_der_b64"])
    cert = x509.Certificate.load(cert_der)
    
    # Build CMS manually with SignedAttributes
    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({
            "type": "content_type",
            "values": ["data"],
        }),
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

    cert_choices = [cms.CertificateChoices({"certificate": cert})]

    signed_data = cms.SignedData({
        "version": "v1",
        "digest_algorithms": cms.DigestAlgorithms([
            algos.DigestAlgorithm({"algorithm": "sha256"})
        ]),
        "encap_content_info": cms.ContentInfo({
            "content_type": "data",
        }),
        "certificates": cms.CertificateSet(cert_choices),
        "signer_infos": cms.SignerInfos([signer_info]),
    })

    cms_content = cms.ContentInfo({
        "content_type": "signed_data",
        "content": signed_data,
    })
    cms_bytes = cms_content.dump()
    
    # Inject CMS
    prep_digest_obj = PreparedByteRangeDigest(
        document_digest=bytes.fromhex(cached["document_digest_hex"]),
        reserved_region_start=cached["reserved_region_start"],
        reserved_region_end=cached["reserved_region_end"],
    )
    
    output = io.BytesIO(cached["pdf_bytes"])
    prep_digest_obj.fill_with_cms(output, cms_bytes)
    output.seek(0)
    
    file_doc = frappe.new_doc("File")
    file_doc.file_name = f"{cached['docname']}_DSC_Signed.pdf"
    file_doc.is_private = 1
    file_doc.content = output.getvalue()
    file_doc.attached_to_doctype = cached["doctype"]
    file_doc.attached_to_name = cached["docname"]
    file_doc.save(ignore_permissions=True)
    
    frappe.cache().delete_value(f"dsc_prep_{session_id}")
    return {"status": "success"}
