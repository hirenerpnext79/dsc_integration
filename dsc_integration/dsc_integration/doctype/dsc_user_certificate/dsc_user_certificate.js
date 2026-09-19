// Copyright (c) 2026, HNS and contributors
// For license information, please see license.txt

frappe.ui.form.on("DSC User Certificate", {
	refresh: function(frm) {
		frm.add_custom_button(__("Register Certificate"), () => {
			register_certificate_from_token(frm);
		});

		const base = "/assets/dsc_integration/downloads/";
		const installers = [
			{ label: __("Windows (64-bit)"), file: "dsc-bridge-1.0.0-windows.zip" },
			{ label: __("Windows (32-bit - Hypersecu/HYP2003)"), file: "dsc-bridge-1.0.0-windows-x86.zip" },
			{ label: __("Linux (Ubuntu/Debian .deb)"), file: "dsc-bridge_1.0.0_amd64.deb" },
			{ label: __("Linux (other, .tar.gz)"), file: "dsc-bridge-1.0.0-linux-amd64.tar.gz" },
		];

		installers.forEach((it) => {
			frm.add_custom_button(
				it.label,
				() => window.open(base + it.file, "_blank"),
				__("Download DSC Bridge")
			);
		});
	},
});

const AGENT_HOST = "127.0.0.1";
const DEFAULT_AGENT_PORT = 4645;

function get_site_token() {
	return window.localStorage.getItem("dsc_site_token") || "";
}

async function ping_agent() {
	try {
		const r = await fetch(`https://${AGENT_HOST}:${DEFAULT_AGENT_PORT}/v1/status`, {
			method: "GET",
			mode: "cors",
		});
		return r.ok ? await r.json() : null;
	} catch (e) {
		return null;
	}
}

function normalise_site_url(u) {
	if (!u) return "";
	try {
		const p = new URL(u);
		return (p.protocol + "//" + p.host).toLowerCase();
	} catch (e) {
		return String(u).replace(/\/+$/, "").toLowerCase();
	}
}

function is_paired(status) {
	const here = normalise_site_url(window.location.origin);
	const paired = (status && status.paired_sites) || [];
	return paired.some((s) => normalise_site_url(s) === here);
}

async function auto_pair() {
	const codeResp = await new Promise((resolve, reject) => {
		frappe.call({
			method: "dsc_integration.dsc_integration.doctype.dsc_user_certificate.dsc_user_certificate.generate_pairing_code",
			callback: (r) =>
				r && r.message
					? resolve(r.message)
					: reject(new Error(__("Could not generate a pairing code."))),
			error: () => reject(new Error(__("Could not generate a pairing code."))),
		});
	});

	const resp = await fetch(`https://${AGENT_HOST}:${DEFAULT_AGENT_PORT}/v1/pair`, {
		method: "POST",
		mode: "cors",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			pairing_code: codeResp.pairing_code,
			site_url: window.location.origin,
		}),
	});
	if (!resp.ok) {
		let detail = "";
		try {
			detail = (await resp.json()).message || "";
		} catch (e) {}
		throw new Error(
			__("Could not pair this computer with the site.") + (detail ? " " + detail : "")
		);
	}
}

async function ensure_paired() {
	const status = await ping_agent();
	if (!status) {
		throw new Error(
			__(
				"Cannot reach the DSC Bridge on this computer. Make sure it is installed and running, then try again."
			)
		);
	}
	if (!is_paired(status)) {
		await auto_pair();
	}
}

async function fetch_token_certs() {
	const url = `https://${AGENT_HOST}:${DEFAULT_AGENT_PORT}/v1/certs`;
	let resp;
	try {
		resp = await fetch(url, {
			method: "GET",
			mode: "cors",
			headers: { "X-DSC-Site-Token": get_site_token() },
		});
	} catch (e) {
		throw new Error(
			__("Cannot reach the dsc-bridge agent at {0}. Is it running and is the token plugged in?", [url])
		);
	}
	if (!resp.ok) {
		throw new Error(__("The agent could not read certificates from the token (HTTP {0}).", [resp.status]));
	}
	const body = await resp.json();
	const certs = (body && body.certs) || [];
	if (!certs.length) {
		throw new Error(__("No certificate found on the connected token."));
	}
	return certs;
}

function register_selected(frm, cert) {
	if (!cert || !cert.cert_der_b64) {
		frappe.msgprint({
			title: __("Cannot register"),
			message: __("The selected certificate did not include its DER data. Update the dsc-bridge agent."),
			indicator: "red",
		});
		return;
	}
	
	frappe.call({
		method: "dsc_integration.dsc_integration.doctype.dsc_user_certificate.dsc_user_certificate.extract_certificate_from_der",
		args: {
			cert_der_b64: cert.cert_der_b64
		},
		freeze: true,
		freeze_message: __("Parsing certificate..."),
		callback: (r) => {
			if (r.message && !r.exc) {
				let data = r.message;
				frm.set_value("user", frappe.session.user);
				frm.set_value("holder_name", data.holder_name);
				frm.set_value("certificate_serial", data.certificate_serial);
				frm.set_value("issuer", data.issuer);
				frm.set_value("valid_from", data.valid_from);
				frm.set_value("valid_until", data.valid_until);
				frm.set_value("certificate_fingerprint", data.certificate_fingerprint);
				frm.set_value("certificate_details", data.certificate_details);
				
				frm.save().then(() => {
					frappe.show_alert({
						message: __('Certificate synced successfully'),
						indicator: 'green'
					});
				});
			}
		}
	});
}

async function register_certificate_from_token(frm) {
	let certs;
	try {
		frappe.dom.freeze(__("Connecting to DSC Bridge..."));
		await ensure_paired();
		certs = await fetch_token_certs();
	} catch (e) {
		frappe.msgprint({ title: __("Register Certificate"), message: e.message, indicator: "red" });
		return;
	} finally {
		frappe.dom.unfreeze();
	}

	if (certs.length === 1) {
		register_selected(frm, certs[0]);
		return;
	}

	const d = new frappe.ui.Dialog({
		title: __("Select Certificate to Register"),
		fields: [
			{
				fieldname: "cert_idx",
				fieldtype: "Select",
				label: __("Certificate"),
				reqd: 1,
				options: certs.map((c, i) => ({
					label: `${c.subject_cn || c.subject_full || __("Certificate")} - ${c.issuer_cn || ""} (${(c.fingerprint_sha256 || "").slice(0, 12)}...)`,
					value: String(i),
				})),
			},
		],
		primary_action_label: __("Register"),
		primary_action(values) {
			d.hide();
			register_selected(frm, certs[Number(values.cert_idx)]);
		},
	});
	d.show();
}
