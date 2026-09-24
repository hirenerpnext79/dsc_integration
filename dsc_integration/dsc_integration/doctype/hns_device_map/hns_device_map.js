// Copyright (c) 2026, HNS and contributors
// For license information, please see license.txt

frappe.ui.form.on("HNS Device Map", {
	refresh(frm) {
		if (frm.is_new()) {
			frm.add_custom_button(__("Fetch Device Info"), async () => {
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
						frm.set_value("person_name", data.hostname || "");
						frm.set_value("device_name", data.hostname || "");
						frm.set_value("os", os_mapped);
						let tech = ``;
						if (data.tech_details) {
							let osStr = data.tech_details.os_version || "";
							if (osStr.toLowerCase().startsWith("windows ")) {
								osStr = osStr.substring(8);
							}
							// Remove redundant Windows build numbers (e.g., "10.0.19045.6466 Build 19045.6466" -> "Build 19045.6466")
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
							tech += `RAM: ${data.tech_details.used_ram_gb.toFixed(2)} GB / ${data.tech_details.total_ram_gb.toFixed(2)} GB Used\n`;
							let formattedDrives = data.tech_details.disk_drives.split(' | ').join('\n  - ');
							tech += `Disk Drives:\n  - ${formattedDrives}\n`;
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
					frappe.msgprint({
						title: __("Cannot Fetch Device Info"),
						message: __("Make sure the DSC Bridge Agent is running on this computer and is updated to the latest version."),
						indicator: "red"
					});
				} finally {
					frappe.dom.unfreeze();
				}
			});
		}
	},
});
