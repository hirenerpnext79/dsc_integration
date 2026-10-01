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
    
    frappe.call = function(options) {
        const method = options.method || options.cmd || (options.args && options.args.cmd);
        const isLogin = (method === 'login');
        const isWorkflow = (method === 'frappe.model.workflow.apply_workflow');
        
        if (isLogin || isWorkflow) {
            let p_dsc = (async () => {
            // Determine user depending on context
            const usr = isLogin ? (options.args ? options.args.usr : options.usr) : (frappe.session && frappe.session.user);
            const w_doctype = isWorkflow ? (typeof options.args.doc === 'string' ? JSON.parse(options.args.doc).doctype : options.args.doc.doctype) : null;
            const w_docname = isWorkflow ? (typeof options.args.doc === 'string' ? JSON.parse(options.args.doc).name : options.args.doc.name) : null;
            const workflow_req_url = '/api/method/dsc_integration.utils.workflow_approval.is_dsc_required';
            const login_req_url = '/api/method/dsc_integration.utils.login.is_dsc_required';
            const workflow_cert_url = '/api/method/dsc_integration.utils.workflow_approval.verify_workflow_certificate';
            const login_cert_url = '/api/method/dsc_integration.utils.login.verify_certificate_mapping';
            
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
                        url: isWorkflow ? workflow_req_url : login_req_url,
                        args: isWorkflow ? { doctype: w_doctype } : { usr: usr },
                        callback: resolve,
                        error: (err) => reject(err)
                    });
                });
                
                if (!requiredCheck || !requiredCheck.message) {
                    return originalFrappeCall.apply(this, arguments); // Proceed normally without DSC
                }

                // 3. Check if the bridge is alive and get certs
                try {
                    await fetch(BRIDGE_BASE + '/v1/status');
                } catch(e) {
                    let certUrl = BRIDGE_BASE + '/v1/status';
                    let msg = `DSC Bridge is not running. Please start the DSC Bridge to perform this action.`;
                    return abortDSC(msg);
                }

                let certResponse;
                let fetchCerts = async () => {
                    return await fetch(BRIDGE_BASE + '/v1/certs', {
                        headers: { "X-DSC-Site-Token": window.localStorage.getItem("dsc_site_token") || "" }
                    });
                };
                
                try {
                    certResponse = await fetchCerts();
                } catch(e) {
                    // Start auto-pairing
                    try {
                        const codeResp = await new Promise((resolve, reject) => {
                            originalFrappeCall({
                                method: "dsc_integration.api.agent.generate_pairing_code",
                                args: { usr: usr },
                                callback: (r) => r && r.message ? resolve(r.message) : reject(new Error(__("Could not generate pairing code"))),
                                error: () => reject(new Error(__("Could not generate pairing code")))
                            });
                        });
                        
                        const pairResp = await fetch(BRIDGE_BASE + '/v1/pair', {
                            method: "POST",
                            mode: "cors",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({
                                pairing_code: codeResp.pairing_code,
                                site_url: window.location.origin,
                            }),
                        });
                        
                        const pairBody = await pairResp.json().catch(() => ({}));
                        if (pairResp.ok) {
                            if (pairBody && pairBody.site_token) {
                                window.localStorage.setItem("dsc_site_token", pairBody.site_token);
                                window.localStorage.setItem("hmac_secret", pairBody.hmac_secret);
                            }
                            // Retry fetching certs now that site is paired
                            certResponse = await fetchCerts();
                        } else {
                            return abortDSC(__("Could not pair this computer with the site.") + (pairBody.message ? " " + pairBody.message : ""));
                        }
                    } catch (pairErr) {
                        return abortDSC(__('Failed to auto-pair with DSC Bridge. ' + pairErr.message));
                    }
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
                                    url: isWorkflow ? workflow_cert_url : login_cert_url,
                                    args: isWorkflow ? { fingerprint: c.fingerprint_sha256, doctype: w_doctype, docname: w_docname } : { usr: usr, fingerprint: c.fingerprint_sha256 },
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
            })();
            p_dsc.abort = function() { console.log("abort ignored"); };
            return p_dsc;
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
                let selected_format = await new Promise(resolve => {
                    frappe.prompt([{
                        label: 'Print Format', 
                        fieldname: 'print_format', 
                        fieldtype: 'Link', 
                        options: 'Print Format', 
                        reqd: 1,
                        get_query: function() {
                            return {
                                filters: {
                                    doc_type: frm.doctype
                                }
                            }
                        }
                    }], 
                    (values) => resolve(values.print_format), __('Select Format'), __('Proceed'));
                });
                
                frappe.show_alert({message: __('Connecting to Local Token...'), indicator: 'blue'});
                let certResp;
                try {
                    certResp = await fetch(`https://${AGENT_HOST}:${PORT}/v1/certs`, {method: "GET", mode: "cors"});
                } catch(e) {
                    throw new Error(__("DSC Bridge is not running. Please start the DSC Bridge to perform this action."));
                }
                if (!certResp.ok) throw new Error(__("Could not read certificate. Is DSC Bridge running?"));
                const certData = await certResp.json();

                if (!certData || !certData.certs || certData.certs.length === 0) {
                    throw new Error("No DSC token detected. Please insert your token.");
                }

                let validCert = null;
                let lastErrorMsg = null;
                for (let i = 0; i < certData.certs.length; i++) {
                    let c = certData.certs[i];
                    if (c && c.fingerprint_sha256) {
                        try {
                            const certCheck = await new Promise((resolve, reject) => {
                                frappe.call({
                                    type: 'POST',
                                    url: '/api/method/dsc_integration.api.direct_dsc.verify_direct_certificate',
                                    args: { fingerprint: c.fingerprint_sha256, doctype: frm.doctype, docname: frm.docname },
                                    callback: resolve,
                                    error: (err) => reject(err)
                                });
                            });
                            
                            if (certCheck && certCheck.message) {
                                if (certCheck.message.status) {
                                    validCert = c;
                                    break;
                                } else {
                                    lastErrorMsg = certCheck.message.msg;
                                }
                            }
                        } catch (e) {
                            console.error(e);
                        }
                    }
                }
                
                if (!validCert) {
                    throw new Error(lastErrorMsg ? lastErrorMsg : __('None of the detected DSC Certificates are assigned to you for signing this document.'));
                }
                
                const cert_der_b64 = validCert.cert_der_b64;
                
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
                let signResp;
                try {
                    signResp = await fetch(`https://${AGENT_HOST}:${PORT}/v1/sign`, {
                        method: "POST", mode: "cors", headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            session_id: session.session_id, hash_to_sign: session.hash_to_sign,
                            hash_algorithm: session.hash_algorithm, expected_fingerprint: validCert.fingerprint_sha256,
                            pin: pin, timestamp: session.hmac_timestamp, nonce: session.hmac_nonce, hmac: session.hmac_signature
                        })
                    });
                } catch(e) {
                    throw new Error(__("DSC Bridge connection lost. Please ensure the DSC Bridge is running."));
                }
                if (!signResp.ok) {
                    const errorText = await signResp.text();
                    let errMsg = "Bridge Error: " + errorText;
                    try {
                        const errJson = JSON.parse(errorText);
                        if (errJson.error === "PIN_INCORRECT" || (errJson.message && errJson.message.includes("CKR_PIN_INCORRECT"))) {
                            errMsg = __("The PIN entered for the DSC Token is incorrect. Please try again.");
                        } else if (errJson.error === "TOKEN_NOT_FOUND" || (errJson.message && errJson.message.includes("TOKEN_NOT_FOUND"))) {
                            errMsg = __("The DSC Token was not found. Please ensure it is plugged in.");
                        } else if (errJson.message) {
                            errMsg = __("DSC Token Error: ") + errJson.message;
                        }
                    } catch(e) { }
                    throw new Error(errMsg);
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
