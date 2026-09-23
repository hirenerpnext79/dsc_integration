frappe.ready(function() {
    if (window.location.pathname !== '/login') return;

    const BRIDGE_BASE = 'https://127.0.0.1:4645';

    // 1. Fetch MAC address and set global header
    fetch(`${BRIDGE_BASE}/v1/mac_address`)
        .then(response => response.json())
        .then(data => {
            const macAddress = data.mac_address || data.mac; 
            if (macAddress) {
                $.ajaxSetup({ headers: { 'X-MAC-Address': macAddress } });
                console.log("DSC Integration: MAC Address attached to headers.");
            }
        })
        .catch(err => console.warn("DSC Integration: Could not connect to dsc_bridge for MAC.", err));


    // 2. Intercept frappe.call for the login command
    const originalFrappeCall = frappe.call;
    
    frappe.call = async function(options) {
        if (options.cmd === 'login' || (options.args && options.args.cmd === 'login')) {
            const usr = options.args ? options.args.usr : options.usr;
            
            try {
                // A. Check if DSC is actually required for this user and device
                const requiredCheck = await new Promise((resolve) => {
                    originalFrappeCall({
                        type: 'POST',
                        url: '/api/method/dsc_integration.utils.login.is_dsc_required',
                        args: { usr: usr },
                        callback: resolve,
                        error: () => resolve({message: false})
                    });
                });
                
                if (!requiredCheck || !requiredCheck.message) {
                    console.log("DSC Integration: DSC is not required for this login. Proceeding normally.");
                    return originalFrappeCall.apply(this, arguments);
                }

                // B. Check if the bridge is alive and get certs
                let certResponse;
                try {
                    certResponse = await fetch(`${BRIDGE_BASE}/v1/certs`);
                                } catch(e) {
                    frappe.msgprint(__("DSC Bridge is not running. Please start the DSC Bridge to login with DSC."));
                    if (frappe.request) frappe.request.cleanup();
                    return; // Abort login
                }
                
                const certData = await certResponse.json();
                if (!certData || !certData.certs || certData.certs.length === 0) {
                    frappe.msgprint("No DSC token detected. Please insert your token.");
                    if (frappe.request) frappe.request.cleanup();
                    return; // Abort login
                }
                
                // Loop through to find a valid cert mapped to the user
                let validCert = null;
                for (let i = 0; i < certData.certs.length; i++) {
                    let c = certData.certs[i];
                    if (c && c.fingerprint_sha256) {
                        // verify with backend if this cert is mapped
                        const certCheck = await new Promise((resolve) => {
                            originalFrappeCall({
                                type: 'POST',
                                url: '/api/method/dsc_integration.utils.login.verify_certificate_mapping',
                                args: { usr: usr, fingerprint: c.fingerprint_sha256 },
                                callback: resolve,
                                error: (err) => resolve({message: {status: false, msg: "Connection error."}})
                            });
                        });
                        
                        if (certCheck && certCheck.message && certCheck.message.status) {
                            validCert = c;
                            break;
                        } else {
                            console.warn("Cert not valid for user:", c.fingerprint_sha256, certCheck?.message?.msg);
                        }
                    }
                }
                
                if (!validCert) {
                    console.error("No mapped DSC certificates found:", certData.certs);
                    frappe.msgprint("This DSC Certificate is not registered to your account.");
                    if (frappe.request) frappe.request.cleanup();
                    return; // Abort login
                }
                
                const cert = validCert;
                console.log(cert)
                // B. Append DSC payload to login args and resume login
                if (!options.args) options.args = {};
                options.args.is_dsc_login = 1;
                options.args.dsc_fingerprint = cert.fingerprint_sha256;

                console.log("DSC Integration: Valid certificate found. Resuming login request.");
                return originalFrappeCall.apply(this, [options]);
                
            } catch (err) {
                console.error("DSC Login Error:", err);
                frappe.msgprint("An error occurred during DSC Login.");
                return; // Abort login
            }
        }
        
        // Pass through any other calls normally
        return originalFrappeCall.apply(this, arguments);
    };
});
