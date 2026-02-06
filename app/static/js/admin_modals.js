document.addEventListener("DOMContentLoaded", function () {
    // USER EDIT - populate fields when edit button is clicked
    document.querySelectorAll(".edit-user-btn").forEach(btn => {
        btn.addEventListener("click", async () => {
            const username = btn.dataset.user;
            try {
                const resp = await fetch(`/admin/api/users/${username}`);
                if (!resp.ok) {
                    alert("Failed to load user data");
                    return;
                }
                const user = await resp.json();
                
                document.getElementById("edit_username").value = user.username || '';
                document.getElementById("edit_email").value = user.email || '';
                document.getElementById("edit_first_name").value = user.first_name || '';
                document.getElementById("edit_last_name").value = user.last_name || '';
                document.getElementById("edit_groups").value = user.groups || '';
            } catch (error) {
                console.error('Error loading user:', error);
                alert("Error loading user data");
            }
        });
    });

    // PASSWORD RESET - populate username when reset button is clicked
    document.querySelectorAll(".reset-password-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const username = btn.dataset.user;
            document.getElementById("reset_username").value = username;
            document.getElementById("reset_username_display").textContent = username;
            document.getElementById("new_password").value = '';
            document.getElementById("confirm_password").value = '';
        });
    });

    // Password confirmation validation
    const resetPasswordForm = document.getElementById("resetPasswordForm");
    if (resetPasswordForm) {
        resetPasswordForm.addEventListener("submit", (e) => {
            const newPass = document.getElementById("new_password").value;
            const confirmPass = document.getElementById("confirm_password").value;
            if (newPass !== confirmPass) {
                e.preventDefault();
                alert("Passwords do not match!");
            }
        });
    }

    // USER SUBMIT - with CSRF handling
    const editUserForm = document.getElementById("editUserForm");
    if (editUserForm) {
        editUserForm.addEventListener("submit", async (e) => {
            e.preventDefault();

            const formData = new FormData(editUserForm);

            try {
                const res = await fetch("/admin/update_user", {
                    method: "POST",
                    body: formData,
                    credentials: "same-origin",
                });

                const contentType = res.headers.get("content-type") || "";

                if (!res.ok) {
                    if (contentType.includes("text/html")) {
                        const html = await res.text();
                        console.error("🔴 HTML error page returned:\n", html);
                        alert("❌ Update failed (likely CSRF missing or expired). Check browser console.");
                        return;
                    } else {
                        const errJson = await res.json();
                        alert("❌ Error: " + (errJson.error || "Unknown error"));
                        return;
                    }
                }

                const json = await res.json();
                if (json.success) {
                    location.reload();
                } else {
                    alert("❌ Error: " + json.error);
                }
            } catch (err) {
                console.error("🔴 Update user failed:", err);
                alert("An unexpected error occurred.");
            }
        });
    }
    // Failsafe: remove lingering backdrop if present after hide
    document.querySelectorAll('.modal-backdrop').forEach(el => el.remove());
    document.body.classList.remove('modal-open');
    document.body.style = '';

});

// SP EDIT
document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".edit-sp-btn").forEach(button => {
        button.addEventListener("click", async () => {
            const spId = button.dataset.spId;
            const response = await fetch(`/admin/api/sp/${spId}`);
            const result = await response.json();

            if (!result.success || !result.sp) {
                alert("Failed to load SP data");
                return;
            }

            const sp = result.sp;

            // Populate fields
            document.getElementById("edit_sp_name").value = sp.name;
            document.getElementById("edit_sp_entity_id").value = sp.entity_id;
            document.getElementById("edit_sp_acs_url").value = sp.acs_url;
            document.getElementById("edit-sp-form").action = `/admin/sp/edit/${sp.id}`;

            // Populate attribute mapping
            const tbody = document.getElementById("edit-claims-body");
            tbody.innerHTML = "";

            const optionsHtml = USER_FIELDS.map(field =>
                `<option value="${field}">${field}</option>`
            ).join("");

            sp.attr_map.forEach((mapping, index) => {
                const row = document.createElement("tr");
                row.innerHTML = `
                <td><input name="claim_name_${index}" class="form-control" value="${mapping.claim}" required></td>
                <td>
                <select name="claim_value_${index}" class="form-select" required>
                    ${optionsHtml}
                </select>
                </td>
                <td class="text-center">
                <button type="button" class="btn btn-sm btn-outline-danger remove-claim">🗑</button>
                </td>
            `;
                tbody.appendChild(row);
                // ✅ THIS LINE FIXES IT
                row.querySelector("select").value = mapping.value;
            });

            bindRemoveHandlers();
            reindexRows("#edit-claims-body");
        });
    });
});




