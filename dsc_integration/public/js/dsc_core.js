$(document).ready(function() {
    const BRIDGE_BASE = 'https://127.0.0.1:4645';

    // 1. Fetch MAC address and set global header
    fetch(BRIDGE_BASE + '/v1/mac_address')
        .then(response => response.json())
        .then(data => {
            const macAddress = data.mac_address || data.mac; 
            if (macAddress) {
                $.ajaxSetup({ headers: { 'X-MAC-Address': macAddress } });
            }
        })
        .catch(err => console.warn('DSC Integration: Could not connect to dsc_bridge for MAC.', err));

    const originalFrappeCall = frappe.call;
    
    frappe.call = async function(options) {
        const method = options.method || options.cmd || (options.args && options.args.cmd);
        const isLogin = (method === 'login');
        const isWorkflow = (method === 'frappe.model.workflow.apply_workflow');
        
        if (isLogin || isWorkflow) {
            // Determine user depending on context
            const usr = isLogin ? (options.args ? options.args.usr : options.usr) : (frappe.session && frappe.session.user);
            
            const abortDSC = (msg) => {
                if (msg) frappe.msgprint(msg);
                
                // Unfreeze standard UI if possible
                if (frappe.dom && frappe.dom.unfreeze) frappe.dom.unfreeze();
                if (options.btn) $(options.btn).prop('disabled', false);
                
                // Cleanup specific to login page
                if (isLogin && frappe.request && frappe.request.cleanup) {
                    frappe.request.cleanup();
                }

                // Trigger standard callbacks
                if (options.always) options.always();
                if (options.error) options.error({message: msg});
                
                return Promise.reject(msg || 'Action Aborted');
            };

            try {
                // 1. First verify if the user is even allowed on this device
                const accessCheck = await new Promise((resolve, reject) => {
                    originalFrappeCall({
                        type: 'POST',
                        url: '/api/method/dsc_integration.utils.login.check_device_access_api',
                        args: { usr: usr },
                        callback: resolve,
                        error: (err) => reject(err)
                    });
                });
                
                // 2. Check if DSC is required for this user and device
                const requiredCheck = await new Promise((resolve, reject) => {
                    originalFrappeCall({
                        type: 'POST',
                        url: '/api/method/dsc_integration.utils.login.is_dsc_required',
                        args: { usr: usr },
                        callback: resolve,
                        error: (err) => reject(err)
                    });
                });
                
                if (!requiredCheck || !requiredCheck.message) {
                    return originalFrappeCall.apply(this, arguments); // Proceed normally without DSC
                }

                // 3. Check if the bridge is alive and get certs
                let certResponse;
                try {
                    certResponse = await fetch(BRIDGE_BASE + '/v1/certs');
                } catch(e) {
                    return abortDSC(__('DSC Bridge is not running. Please start the DSC Bridge to perform this action.'));
                }
                
                const certData = await certResponse.json();
                if (!certData || !certData.certs || certData.certs.length === 0) {
                    return abortDSC(__('No DSC token detected. Please insert your token.'));
                }
                
                // 4. Loop through to find a valid cert mapped to the user
                let validCert = null;
                for (let i = 0; i < certData.certs.length; i++) {
                    let c = certData.certs[i];
                    if (c && c.fingerprint_sha256) {
                        try {
                            const certCheck = await new Promise((resolve, reject) => {
                                originalFrappeCall({
                                    type: 'POST',
                                    url: '/api/method/dsc_integration.utils.login.verify_certificate_mapping',
                                    args: { usr: usr, fingerprint: c.fingerprint_sha256 },
                                    callback: resolve,
                                    error: (err) => reject(err)
                                });
                            });
                            
                            if (certCheck && certCheck.message && certCheck.message.status) {
                                validCert = c;
                                break;
                            }
                        } catch (e) {
                            return abortDSC(); 
                        }
                    }
                }
                
                if (!validCert) {
                    return abortDSC(__('This DSC Certificate is not registered to your account.'));
                }

                // 5. Valid certificate found. Append fingerprint
                if (isLogin) {
                    if (!options.args) options.args = {};
                    options.args.is_dsc_login = 1;
                    options.args.dsc_fingerprint = validCert.fingerprint_sha256;
                } else if (isWorkflow) {
                    if (options.args && options.args.doc) {
                        try {
                            let doc = typeof options.args.doc === 'string' ? JSON.parse(options.args.doc) : options.args.doc;
                            doc.dsc_fingerprint = validCert.fingerprint_sha256;
                            options.args.doc = typeof options.args.doc === 'string' ? JSON.stringify(doc) : doc;
                        } catch(e) {
                            console.error("Could not parse doc for DSC workflow", e);
                        }
                    }
                }
                
                // Proceed with original action
                return originalFrappeCall.apply(this, [options]);
                
            } catch (err) {
                console.error('Validation Error:', err);
                if (frappe.dom && frappe.dom.unfreeze) frappe.dom.unfreeze();
                return abortDSC();
            }
        }
        
        // For all other methods, just pass through
        return originalFrappeCall.apply(this, arguments);
    };
});
// DSC Generalized Signing Logic

if (frappe.boot.dsc_supported_doctypes && frappe.boot.dsc_supported_doctypes.length > 0) {
    frappe.boot.dsc_supported_doctypes.forEach(function(doctype) {
frappe.ui.form.on(doctype, {
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

    });
}
