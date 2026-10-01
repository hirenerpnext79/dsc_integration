frappe.listview_settings['HNS DSC Log'] = {
    onload: function(listview) {
		listview.page.clear_primary_action();
        setTimeout(() => {
            $('.primary-action').hide();
        }, 10);
	}
};