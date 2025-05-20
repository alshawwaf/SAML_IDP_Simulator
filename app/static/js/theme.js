document.addEventListener("DOMContentLoaded", () => {
    const toggleBtn = document.getElementById("toggleDarkMode");

    // Apply stored theme on load
    if (localStorage.getItem("theme") === "dark") {
        document.body.classList.add("dark-mode");
    }

    // Toggle on click
    toggleBtn?.addEventListener("click", () => {
        document.body.classList.toggle("dark-mode");
        const theme = document.body.classList.contains("dark-mode") ? "dark" : "light";
        localStorage.setItem("theme", theme);
    });
});
