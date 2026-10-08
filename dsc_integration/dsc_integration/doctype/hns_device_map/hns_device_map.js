// Copyright (c) 2026, HNS and contributors
// For license information, please see license.txt

frappe.ui.form.on("HNS Device Map", {
	refresh(frm) {
		frm.add_custom_button(__("Fetch Device Info"), async () => {
			await frm.events.fetch_from_dsc_bridge(frm);
		});
	},
	
	async fetch_from_dsc_bridge(frm) {
		try {
			const AGENT_HOST = "127.0.0.1";
			const DEFAULT_AGENT_PORT = 4645;
			
			frappe.dom.freeze(__("Connecting to local DSC Agent..."));
			
			const r = await fetch(`https://${AGENT_HOST}:${DEFAULT_AGENT_PORT}/v1/status`, {
				method: "GET",
				mode: "cors",
			});
			
			if (r.ok) {
				const data = await r.json();
				
				let os_mapped = data.platform;
				if (data.platform === "windows") os_mapped = "Window";
				else if (data.platform === "darwin") os_mapped = "Mac OS";
				else if (data.platform === "linux") os_mapped = "Linux";
				
				frm.set_value("mac_address", data.mac_address || "");
				if(!frm.doc.person_name){
					frm.set_value("person_name", data.hostname || "");
				}

				frm.set_value("device_name", data.hostname || "");
				frm.set_value("os", os_mapped);
				let tech = ``;
				if (data.tech_details) {
					let osStr = data.tech_details.os_version || "";
					if (osStr.toLowerCase().startsWith("windows ")) {
						osStr = osStr.substring(8);
					}
					// Remove redundant Windows build numbers
					osStr = osStr.replace(/ \d+\.\d+\.\d+\.\d+ (Build \d+\.\d+)/, " $1");
					let techOsLine = `OS Version: ${osStr}`;
					if (data.tech_details.system_arch) {
						techOsLine += ` (${data.tech_details.system_arch})`;
					}
					if (data.tech_details.kernel_version && !osStr.includes(data.tech_details.kernel_version)) {
						techOsLine += ` (Kernel: ${data.tech_details.kernel_version})`;
					}
					tech += techOsLine + `\n`;
					tech += `CPU: ${data.tech_details.cpu_model} (${data.tech_details.cpu_cores} cores @ ${data.tech_details.cpu_mhz} MHz)\n`;
					let ramLine = `RAM: ${data.tech_details.used_ram_gb.toFixed(2)} GB / ${data.tech_details.total_ram_gb.toFixed(2)} GB Used`;
							if (data.tech_details.installed_ram_gb) {
								ramLine = `Installed RAM: ${data.tech_details.installed_ram_gb.toFixed(2)} GB (${data.tech_details.total_ram_gb.toFixed(2)} GB usable) - ${data.tech_details.used_ram_gb.toFixed(2)} GB Used`;
							}
							tech += ramLine + '\n';
					let formattedDrives = data.tech_details.disk_drives.split(' | ').join('\n  - ');
					tech += `Storage:\n  - ${formattedDrives}\n`;
					tech += `Logged Users: ${data.tech_details.logged_users || 'None'}`;
				}
				frm.set_value("device_tech_details", tech);
				
				frappe.show_alert({
					message: __('Device info fetched successfully from local PC'),
					indicator: 'green'
				});
			} else {
				throw new Error("Agent returned error status");
			}
		} catch (e) {
			await frm.events.fetch_local_mac_address(frm);
		} finally {
			frappe.dom.unfreeze();
		}
	},

	async fetch_local_mac_address(frm) {
		frappe.dom.freeze(__("Fetching MAC Address via fallback..."));
		try {
			await frappe.call({
				method: "dsc_integration.dsc_integration.doctype.hns_device_map.hns_device_map.get_physical_mac",
				callback: function(r) {
					if (r.message) {
						for (let field in r.message) {
							if (r.message[field]) {
								frm.set_value(field, r.message[field]);
							}
						}
						
						frappe.show_alert({
							message: __("MAC Address fetched successfully"),
							indicator: "green"
						});
					} else {
						frappe.msgprint({
							title: __("Cannot Fetch MAC Address"),
							message: __("Make sure the DSC Bridge Agent is running on this computer and is updated to the latest version."),
							indicator: "red"
						});
					}
				}
			});
		} finally {
			frappe.dom.unfreeze();
		}
	}
});
