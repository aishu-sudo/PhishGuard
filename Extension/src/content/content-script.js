// PhishGuard content script.
//
// The dismissable in-page banner has been removed. RED and YELLOW
// results now both redirect to warning.html (see service-worker.js),
// so there is no longer an in-page alert for this script to render.
// Kept as an empty listener in case a future feature needs to message
// into the page again.

chrome.runtime.onMessage.addListener((msg) => {
    // Currently unused — RED/YELLOW both go through warning.html.
});