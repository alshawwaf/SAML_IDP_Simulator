// Group management modal behavior — mirrors admin_modals.js (user edit).
document.addEventListener("DOMContentLoaded", () => {
    // EDIT GROUP — fetch group data and populate the modal (incl. member checkboxes)
    document.querySelectorAll(".edit-group-btn").forEach(btn => {
        btn.addEventListener("click", async () => {
            const groupPk = btn.dataset.groupPk;
            try {
                const resp = await fetch(`/admin/api/groups/${groupPk}`);
                if (!resp.ok) {
                    alert("Failed to load group data");
                    return;
                }
                const g = await resp.json();
                document.getElementById("edit_group_pk").value = g.id;
                document.getElementById("edit_display_name").value = g.display_name || "";
                document.getElementById("edit_description").value = g.description || "";
                document.getElementById("edit_group_id_display").textContent = g.group_id || "";

                const members = new Set(g.member_user_ids || []);
                document.querySelectorAll(".edit-member-check").forEach(cb => {
                    cb.checked = members.has(parseInt(cb.value, 10));
                });
            } catch (err) {
                console.error("Error loading group:", err);
                alert("Error loading group data");
            }
        });
    });

    // EDIT GROUP — submit via fetch (JSON response), mirroring update_user handling
    const editGroupForm = document.getElementById("editGroupForm");
    if (editGroupForm) {
        editGroupForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const formData = new FormData(editGroupForm);
            try {
                const res = await fetch("/admin/update_group", {
                    method: "POST",
                    body: formData,
                    credentials: "same-origin",
                });
                const contentType = res.headers.get("content-type") || "";
                if (!res.ok) {
                    if (contentType.includes("application/json")) {
                        const errJson = await res.json();
                        alert("❌ Error: " + (errJson.error || "Unknown error"));
                    } else {
                        console.error("🔴 HTML error page returned:\n", await res.text());
                        alert("❌ Update failed (likely CSRF missing or expired). Check browser console.");
                    }
                    return;
                }
                const json = await res.json();
                if (json.success) location.reload();
                else alert("❌ Error: " + json.error);
            } catch (err) {
                console.error("🔴 Update group failed:", err);
                alert("An unexpected error occurred.");
            }
        });
    }

    // Member-list filter (add + edit modals): type to narrow the checkbox list.
    document.querySelectorAll(".member-filter").forEach(input => {
        input.addEventListener("input", () => {
            const list = document.getElementById(input.dataset.target);
            if (!list) return;
            const q = input.value.trim().toLowerCase();
            list.querySelectorAll(".member-row").forEach(row => {
                row.style.display = row.textContent.toLowerCase().includes(q) ? "" : "none";
            });
        });
    });
});
