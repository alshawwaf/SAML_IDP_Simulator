document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".edit-user-btn").forEach(button => {
        button.addEventListener("click", () => {
            const user = JSON.parse(button.dataset.user);
            for (const [key, value] of Object.entries(user)) {
                const input = document.getElementById(`edit_${key}`);
                if (input) input.value = value;
            }
        });
    });

    const editForm = document.getElementById("editUserForm");
    if (editForm) {
        editForm.addEventListener("submit", async e => {
            e.preventDefault();
            const formData = new FormData(editForm);
            const res = await fetch("/admin/update_user", {
                method: "POST",
                body: formData,
            });
            const json = await res.json();
            if (json.success) location.reload();
            else alert("Error: " + json.error);
        });
    }
});


