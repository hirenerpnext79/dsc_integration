// Copyright (c) 2024, hns and contributors
// For license information, please see license.txt

frappe.ui.form.on('DSC Format Setting', {
    setup: function(frm) {
        frm.set_query('print_format', 'format_settings', function(doc, cdt, cdn) {
            if (frm.doc.ref_doctype) {
                return {
                    filters: {
                        'doc_type': frm.doc.ref_doctype
                    }
                };
            }
        });
    }
});
