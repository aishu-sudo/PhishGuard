const params = new URLSearchParams(window.location.search);
const targetUrl = params.get("url");
const decodedUrl = targetUrl ? decodeURIComponent(targetUrl) : null;
const tabIdParam = params.get("tabId");
const tabId = tabIdParam !== null ? Number(tabIdParam) : null;

function goToWarning(level, score) {
    const warningUrl =
        chrome.runtime.getURL("warning.html") +
        "?url=" + encodeURIComponent(decodedUrl) +
        "&level=" + encodeURIComponent(level) +
        "&score=" + encodeURIComponent(String(score)) +
        "&tabId=" + encodeURIComponent(String(tabId));
    window.location.replace(warningUrl);
}

if (!decodedUrl) {
    // Nothing to check — shouldn't normally happen, fail safe by just
    // stopping here rather than guessing a destination.
    document.querySelector("p").textContent = "Missing URL — close this tab.";
} else {
    chrome.runtime.sendMessage({ type: "PG_CHECK_NOW", url: decodedUrl, tabId: tabId },
        function(response) {
            if (chrome.runtime.lastError || !response || !response.ok) {
                // Backend unreachable or worker error — do NOT silently
                // continue to the site. Treat as unknown/unsafe.
                goToWarning("UNKNOWN", 0);
                return;
            }

            if (response.safe) {
                // Background has already recorded a bypass for this exact
                // tab+url, so this navigation will not be re-intercepted.
                window.location.replace(decodedUrl);
            } else {
                goToWarning(response.level, response.score);
            }
        }
    );
}