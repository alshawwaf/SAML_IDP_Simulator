document.addEventListener("DOMContentLoaded", function () {
    const viewBtn = document.getElementById("viewMetadataBtn");
    const metadataContainer = document.getElementById("metadataContent");
    const copyBtn = document.getElementById("copyMetadataBtn");

    if (viewBtn && metadataContainer) {
        viewBtn.addEventListener("click", () => {
            fetch("/metadata")
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}`);
                    }
                    return response.text();
                })
                .then(xmlText => {
                    const formatted = (typeof vkbeautify !== "undefined")
                        ? vkbeautify.xml(xmlText)
                        : xmlText; // Fallback if vkbeautify is missing
                    metadataContainer.textContent = formatted;
                    Prism.highlightElement(metadataContainer);
                })
                .catch(err => {
                    metadataContainer.textContent = "⚠️ Failed to load metadata.";
                    console.error("Metadata fetch error:", err);
                });
        });
    }

    if (copyBtn && metadataContainer) {
        copyBtn.addEventListener("click", () => {
            const text = metadataContainer.textContent || "";
            navigator.clipboard.writeText(text)
                .then(() => {
                    copyBtn.innerHTML = '<i class="bi bi-clipboard-check me-1"></i> Copied!';
                    setTimeout(() => {
                        copyBtn.innerHTML = '<i class="bi bi-clipboard me-1"></i> Copy to Clipboard';
                    }, 2000);
                })
                .catch(err => {
                    console.error("Copy failed:", err);
                });
        });
    }
});
