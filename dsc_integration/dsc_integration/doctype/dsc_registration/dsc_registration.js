// Pairing UI for DSC Registration.
//
// "Pair This Computer" does one-click pairing: the browser asks the server for
// a one-time code, then hands that code straight to the local dsc-bridge agent
// at https://127.0.0.1:<port>/v1/pair — no code to copy, no curl to run. This
// is the same browser-to-localhost-agent pattern e_sign.js uses for signing.
//
// The whole file is wrapped in an IIFE: this doctype's controller JS is loaded
// more than once (it is both auto-loaded from the doctype folder and listed in
// hooks.py doctype_js), so top-level `const`s would otherwise throw
// "redeclaration of const" and crash the form.

(function () {
"use strict";

const AGENT_HOST = "127.0.0.1";
const DEFAULT_AGENT_PORT = 4645;

frappe.ui.form.on("DSC Registration", {
	refresh(frm) {
		const $pair = frm.add_custom_button(__("Pair This Computer"), () =>
			pairThisComputer(frm)
		);
		$pair.removeClass("btn-default").addClass("btn-primary");


	},
});

// ---------------------------------------------------------------------------
// One-click automatic pairing
// ---------------------------------------------------------------------------

async function pairThisComputer(frm) {
	const port = await getAgentPort();
	frappe.dom.freeze(__("Pairing this computer…"));
	try {
		// 1. Confirm the local dsc-bridge agent is reachable.
		const status = await pingAgent(port);
		if (!status) {
			throw new AgentUnreachable(port);
		}

		// 2. Mint a one-time pairing code on the server.
		const codeResp = await callServer("dsc_integration.api.agent.generate_pairing_code");
		if (!codeResp || !codeResp.pairing_code) {
			throw new Error(__("The server did not return a pairing code."));
		}

		// 3. Hand the code straight to the local agent — it validates the code
		//    against the site and stores the long-lived site token itself.
		//    site_url is the browser's own origin, i.e. the exact host:port the
		//    user is currently on. This avoids the server-side get_url() falling
		//    back to the bench's configured webserver_port (which can differ from
		//    the port actually being used), so the agent always calls back a URL
		//    that resolves — whatever bench port is in use.
		const resp = await fetch(`https://${AGENT_HOST}:${port}/v1/pair`, {
			method: "POST",
			mode: "cors",
			headers: { "Content-Type": "application/json", "X-DSC-Site-Token": window.localStorage.getItem("dsc_site_token") || "" },
			body: JSON.stringify({
				pairing_code: codeResp.pairing_code,
				site_url: window.location.origin,
			}),
		});
		const body = await resp.json().catch(() => ({}));
		if (resp.ok && body && body.site_token) {
		window.localStorage.setItem("dsc_site_token", body.site_token);
	}
	if (!resp.ok) {
			throw new Error(
				body.message ||
					body.error ||
					__("The agent could not complete pairing.")
			);
		}

		frappe.dom.unfreeze();
		frappe.show_alert(
			{ message: __("This computer is paired ✓"), indicator: "green" },
			6
		);
		// validate_pairing_code created a fresh DSC Registration row —
		// drop the user on the list so they see it.
		setTimeout(() => frappe.set_route("List", "DSC Registration"), 900);
	} catch (err) {
		frappe.dom.unfreeze();
		showPairError(err, port);
	}
}


// Marker error so showPairError can give agent-specific guidance.
function AgentUnreachable(port) {
	this.name = "AgentUnreachable";
	this.port = port;
	this.message = __("The DSC Bridge agent is not reachable on this computer.");
}

async function pingAgent(port) {
	try {
		const r = await fetch(`https://${AGENT_HOST}:${port}/v1/status`, {
			method: "GET",
			mode: "cors",
		});
		return r.ok ? await r.json() : null;
	} catch (e) {
		return null;
	}
}

async function getAgentPort() {
	try {
		const v = await frappe.db.get_single_value("DSC Agent Settings", "agent_listen_port");
		return parseInt(v, 10) || DEFAULT_AGENT_PORT;
	} catch (e) {
		return DEFAULT_AGENT_PORT;
	}
}

function callServer(method, args) {
	return new Promise((resolve, reject) => {
		frappe.call({
			method,
			args,
			callback: (r) => resolve(r ? r.message : null),
			error: reject,
		});
	});
}

function showPairError(err, port) {
	const statusUrl = `https://${AGENT_HOST}:${port}/v1/status`;
	let message;
	if (err && err.name === "AgentUnreachable") {
		// Most often: agent not running, or the browser hasn't accepted the
		// agent's self-signed certificate yet.
		message =
			__("The DSC Bridge agent could not be reached on this computer.") +
			"<br><br>" +
			__("Check that:") +
			`<ul>
				<li>${__("the DSC Bridge agent is installed and running")}</li>
				<li>${__("it is listening on port {0}", [port])}</li>
			</ul>` +
			__(
				"If it is running, your browser may be blocking its self-signed certificate. Open {0} once in a new tab, accept the security warning, then click Pair again.",
				[`<a href='${statusUrl}' target='_blank'>${statusUrl}</a>`]
			);
	} else {
		message =
			frappe.utils.escape_html((err && err.message) || String(err));
	}
	frappe.msgprint({ title: __("Pairing failed"), indicator: "red", message });
}


})();
