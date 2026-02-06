// XML Syntax highlighting function
function highlightXML(xml) {
    // Escape HTML entities first
    let escaped = xml
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    
    // Apply syntax highlighting with clear, readable colors
    escaped = escaped
        // Comments - gray
        .replace(/(&lt;!--[\s\S]*?--&gt;)/g, '<span style="color:#6a737d">$1</span>')
        // XML declaration - purple
        .replace(/(&lt;\?[\s\S]*?\?&gt;)/g, '<span style="color:#d2a8ff">$1</span>')
        // Tag names - green
        .replace(/(&lt;\/?)([\w][\w:-]*)/g, '$1<span style="color:#7ee787">$2</span>')
        // Attribute names - blue
        .replace(/([\w:-]+)(=)(&quot;)/g, '<span style="color:#79c0ff">$1</span>$2$3')
        // Attribute values - light blue
        .replace(/(&quot;)([^&]*)(&quot;)/g, '$1<span style="color:#a5d6ff">$2</span>$3')
        // Brackets - green
        .replace(/(&gt;)/g, '<span style="color:#7ee787">$1</span>')
        .replace(/(&lt;)/g, '<span style="color:#7ee787">$1</span>');
    
    return escaped;
}

document.addEventListener("DOMContentLoaded", function () {
    const viewBtn = document.getElementById("viewMetadataBtn");
    const metadataContainer = document.getElementById("metadataContent");
    const copyBtn = document.getElementById("copyMetadataBtn");

    // Store raw XML for copying
    let rawXML = "";

    if (viewBtn && metadataContainer) {
        viewBtn.addEventListener("click", () => {
            metadataContainer.innerHTML = '<span class="text-muted">Loading...</span>';
            
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
                        : xmlText;
                    rawXML = formatted;
                    metadataContainer.innerHTML = highlightXML(formatted);
                })
                .catch(err => {
                    metadataContainer.innerHTML = '<span class="text-danger">⚠️ Failed to load metadata.</span>';
                    console.error("Metadata fetch error:", err);
                });
        });
    }

    if (copyBtn && metadataContainer) {
        copyBtn.addEventListener("click", () => {
            navigator.clipboard.writeText(rawXML || metadataContainer.textContent)
                .then(() => {
                    copyBtn.innerHTML = '<i class="bi bi-clipboard-check me-1"></i>Copied!';
                    setTimeout(() => {
                        copyBtn.innerHTML = '<i class="bi bi-clipboard me-1"></i>Copy XML';
                    }, 2000);
                })
                .catch(err => {
                    console.error("Copy failed:", err);
                });
        });
    }
});
