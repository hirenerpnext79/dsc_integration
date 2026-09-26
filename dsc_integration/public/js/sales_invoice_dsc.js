frappe.ui.form.on('Sales Invoice', {
    refresh(frm) {
        frm.add_custom_button(__('Sign with Token'), async function () {
            const AGENT_HOST = "127.0.0.1";
            const PORT = 4645;
            
            try {
                let print_formats = frappe.meta.get_print_formats(frm.doctype);
                let selected_format = await new Promise(resolve => {
                    frappe.prompt([{label: 'Print Format', fieldname: 'print_format', fieldtype: 'Select', options: print_formats, default: print_formats[0], reqd: 1}], 
                    (values) => resolve(values.print_format), __('Select Format'), __('Proceed'));
                });
                
                frappe.show_alert({message: __('Connecting to Local Token...'), indicator: 'blue'});
                const certResp = await fetch(`https://${AGENT_HOST}:${PORT}/v1/certs`, {method: "GET", mode: "cors"});
                if (!certResp.ok) throw new Error("Could not read certificate. Is DSC Bridge running?");
                const certBody = await certResp.json();
                if (!certBody.certs || !certBody.certs.length) throw new Error("No certificate found on token.");
                
                const cert_der_b64 = certBody.certs[0].cert_der_b64;
                
                frappe.show_alert({message: __('Preparing PDF...'), indicator: 'blue'});
                const initResp = await frappe.call({
                    method: 'dsc_integration.api.direct_dsc.initiate_direct_sign',
                    args: { doctype: frm.doctype, docname: frm.docname, print_format: selected_format, cert_der_b64: cert_der_b64 }
                });
                const session = initResp.message;
                
                let pin = await new Promise(resolve => {
                    frappe.prompt([{fieldtype: 'Password', fieldname: 'pin', label: 'Token PIN', reqd: 1}], 
                    (values) => resolve(values.pin), __('Enter PIN'), __('Sign'));
                });
                
                frappe.show_alert({message: __('Signing with Token...'), indicator: 'blue'});
                const signResp = await fetch(`https://${AGENT_HOST}:${PORT}/v1/sign`, {
                    method: "POST", mode: "cors", headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_id: session.session_id, hash_to_sign: session.hash_to_sign,
                        hash_algorithm: session.hash_algorithm, expected_fingerprint: certBody.certs[0].fingerprint_sha256,
                        pin: pin, timestamp: session.hmac_timestamp, nonce: session.hmac_nonce, hmac: session.hmac_signature
                    })
                });
                if (!signResp.ok) {
                    const errorText = await signResp.text();
                    throw new Error("Bridge Error: " + errorText);
                }
                const signedBody = await signResp.json();
                
                frappe.show_alert({message: __('Finalizing PDF...'), indicator: 'blue'});
                const finalResp = await frappe.call({
                    method: 'dsc_integration.api.direct_dsc.finalize_direct_sign',
                    args: { 
                        doctype: frm.doctype,
                        docname: frm.docname,
                        session_id: session.session_id, 
                        signature_hex: signedBody.signature_hex || signedBody.signature || signedBody.signature_bytes_b64
                    }
                });
                
                if (finalResp.message.status === 'success') {
                    frappe.msgprint(__('Successfully signed and attached the PDF!'));
                    frm.reload_doc();
                }
            } catch (err) {
                frappe.msgprint({title: __('Error'), message: err.message, indicator: 'red'});
            }
        });
    }
});
