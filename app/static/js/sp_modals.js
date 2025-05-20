document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".edit-sp-btn").forEach(button => {
        button.addEventListener("click", () => {
            const sp = JSON.parse(button.dataset.sp);
            document.getElementById("edit_sp_id").value = sp.id;
            document.getElementById("edit_sp_name").value = sp.name;
            document.getElementById("edit_sp_entity_id").value = sp.entity_id;
            document.getElementById("edit_sp_acs_url").value = sp.acs_url;
            // TODO: fill attribute mappings
        });
    });
});


