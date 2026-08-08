import { predictFast, investigateURL } from "../api/client";
import { setCachedResult } from "../utils/storage";

const BADGE_COLORS = {
    RED: "#dc2626",
    YELLOW: "#f59e0b",
    GREEN: "#16a34a",
    UNKNOWN: "#9ca3af",
};

const inFlight = new Map();
const bypassed = new Map(); // tabId -> Set of exact bypassed URLs
const suppressUntil = new Map(); // tabId -> timestamp (ms) — short grace
// window right after "Proceed Anyway",
// since the target site itself may
// rewrite the URL on navigation and
// break an exact-string bypass match.
const SUPPRESS_WINDOW_MS = 10000;

const SKIP_PREFIXES = [
    "chrome://", "chrome-extension://", "about:", "edge://", "brave://",
    "devtools://", "view-source:", "file://", "data:", "blob:",
    "moz-extension://", "javascript:",
];

function shouldSkip(url) {
    if (!url) return true;
    const lower = url.toLowerCase();
    if (SKIP_PREFIXES.some((p) => lower.startsWith(p))) return true;
    if (lower.includes("warning.html") || lower.includes("checking.html")) return true;
    return !(lower.startsWith("http://") || lower.startsWith("https://"));
}

function isWellFormed(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

function isBypassed(tabId, url) {
    const until = suppressUntil.get(tabId);
    if (until && Date.now() < until) return true;

    const set = bypassed.get(tabId);
    return Boolean(set && set.has(url));
}

function addBypass(tabId, url) {
    if (!bypassed.has(tabId)) bypassed.set(tabId, new Set());
    const set = bypassed.get(tabId);
    set.add(url);
    if (set.size > 30) set.delete(set.values().next().value);

    // The grace window is what actually prevents the loop — it covers
    // any URL the site rewrites to immediately after this navigation,
    // not just the exact string the user clicked through on.
    suppressUntil.set(tabId, Date.now() + SUPPRESS_WINDOW_MS);
}

function safeScore(value) {
    const n = Number(value);
    if (!Number.isFinite(n)) return 0;
    return Math.min(1, Math.max(0, n));
}

function setBadge(tabId, level) {
    const text = level === "RED" ? "!" : level === "YELLOW" ? "?" : "";
    chrome.action.setBadgeText({ tabId, text }).catch(() => {});
    chrome.action
        .setBadgeBackgroundColor({
            tabId,
            color: BADGE_COLORS[level] || BADGE_COLORS.UNKNOWN,
        })
        .catch(() => {});
}

function sendToChecking(tabId, url) {
    if (shouldSkip(url)) return;
    if (!isWellFormed(url)) {
        console.warn("[PhishGuard] skipping malformed URL:", url);
        return;
    }
    if (isBypassed(tabId, url)) return;
    if (inFlight.get(tabId) === url) return;

    inFlight.set(tabId, url);

    const checkingUrl =
        chrome.runtime.getURL("checking.html") +
        "?url=" + encodeURIComponent(url) +
        "&tabId=" + encodeURIComponent(String(tabId));

    chrome.tabs.update(tabId, { url: checkingUrl });
}

async function runFastCheck(tabId, url) {
    try {
        const result = await predictFast(url);

        const level = (result && result.alert_level) || "UNKNOWN";
        const score = safeScore(result && result.fused_score);

        const normalized = {...result, fused_score: score, alert_level: level };
        await setCachedResult(url, normalized);

        setBadge(tabId, level);

        if (level === "RED" || level === "YELLOW") {
            return { ok: true, safe: false, level, score };
        }

        addBypass(tabId, url);
        return { ok: true, safe: true, level, score };

    } catch (err) {
        console.error("[PhishGuard] check failed for", url, err);
        setBadge(tabId, "UNKNOWN");
        await setCachedResult(url, {
            url,
            alert_level: "UNKNOWN",
            fused_score: 0,
            error: String((err && err.message) || err),
        });
        return { ok: true, safe: false, level: "UNKNOWN", score: 0 };
    } finally {
        if (inFlight.get(tabId) === url) inFlight.delete(tabId);
    }
}

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0) return;
    sendToChecking(details.tabId, details.url);
});

chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId !== 0) return;
    if (!(details.transitionQualifiers && details.transitionQualifiers.includes("server_redirect"))) return;
    sendToChecking(details.tabId, details.url);
});

chrome.webNavigation.onTabReplaced.addListener((details) => {
    chrome.tabs.get(details.tabId, (tab) => {
        if (chrome.runtime.lastError || !tab || !tab.url) return;
        sendToChecking(details.tabId, tab.url);
    });
});

chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
    if (details.frameId !== 0) return;
    const { tabId, url } = details;
    if (shouldSkip(url)) return;
    if (!isWellFormed(url)) return;
    if (isBypassed(tabId, url)) return;
    if (inFlight.get(tabId) === url) return;

    inFlight.set(tabId, url);
    runFastCheck(tabId, url).then((verdict) => {
        if (!verdict.safe) {
            const warningUrl =
                chrome.runtime.getURL("warning.html") +
                "?url=" + encodeURIComponent(url) +
                "&level=" + encodeURIComponent(verdict.level) +
                "&score=" + encodeURIComponent(String(verdict.score)) +
                "&tabId=" + encodeURIComponent(String(tabId));
            chrome.tabs.update(tabId, { url: warningUrl });
        }
    });
});

chrome.tabs.onRemoved.addListener((tabId) => {
    inFlight.delete(tabId);
    bypassed.delete(tabId);
    suppressUntil.delete(tabId);
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg && msg.type === "PG_CHECK_NOW") {
        const tabId =
            msg.tabId !== undefined && msg.tabId !== null ?
            msg.tabId :
            (sender.tab && sender.tab.id);
        if (tabId == null || !msg.url) {
            sendResponse({ ok: false, error: "missing tabId or url" });
            return true;
        }
        inFlight.set(tabId, msg.url);
        runFastCheck(tabId, msg.url).then(sendResponse);
        return true;
    }

    if (msg && msg.type === "PG_PROCEED_ANYWAY") {
        const tabId =
            msg.tabId !== undefined && msg.tabId !== null ?
            msg.tabId :
            (sender.tab && sender.tab.id);
        if (tabId != null && msg.url) {
            addBypass(tabId, msg.url);
            chrome.tabs.update(tabId, { url: msg.url });
        }
        sendResponse({ ok: true });
        return true;
    }

    if (msg && msg.type === "PG_INVESTIGATE") {
        investigateURL(msg.url)
            .then((data) => sendResponse({ ok: true, data }))
            .catch((e) => sendResponse({ ok: false, error: String((e && e.message) || e) }));
        return true;
    }

    return false;
});