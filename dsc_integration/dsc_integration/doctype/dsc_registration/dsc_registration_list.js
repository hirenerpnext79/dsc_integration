frappe.listview_settings['DSC Registration'] = {
	onload: function(listview) {
        listview.page.clear_primary_action();
        setTimeout(() => {
            $('.primary-action').hide();
        }, 10);
	}
};
