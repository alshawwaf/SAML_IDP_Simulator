document.addEventListener("DOMContentLoaded", () => {
    const toggleBtn = document.getElementById("toggleDarkMode");

    // Apply stored theme on load
    if (localStorage.getItem("theme") === "dark") {
        document.documentElement.classList.add("dark-mode");
    }

    // Toggle theme on button click
    toggleBtn?.addEventListener("click", () => {
        document.documentElement.classList.toggle("dark-mode");
        const isDark = document.documentElement.classList.contains("dark-mode");
        localStorage.setItem("theme", isDark ? "dark" : "light");

        updateSelectStyles(); // update select styles on toggle
    });

    // Initial style update for selects
    updateSelectStyles();
});

/**
 * Applies or removes dark styles to <select> elements
 */
function updateSelectStyles() {
    const isDark = document.documentElement.classList.contains("dark-mode");
    document.querySelectorAll("select").forEach((sel) => {
        sel.classList.toggle("bg-dark", isDark);
        sel.classList.toggle("text-light", isDark);
    });
}
