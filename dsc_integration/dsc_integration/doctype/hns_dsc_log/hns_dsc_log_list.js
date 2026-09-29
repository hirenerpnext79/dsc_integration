frappe.listview_settings['HNS DSC Log'] = {
    onload: function(listview) {
        listview.page.clear_primary_action();
        
        // Aggressively hide the button in case it renders late
        setTimeout(() => {
            listview.page.clear_primary_action();
            $('.primary-action').hide();
        }, 50);
        setTimeout(() => {
            $('.primary-action').hide();
        }, 500);
    }
};