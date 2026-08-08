import { API_BASE } from "../utils/constants";

export async function predictURL(url, timeoutMs = 90000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const res = await fetch(`${API_BASE}/predict/url`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
            signal: controller.signal,
        });
        if (!res.ok) throw new Error(`API error ${res.status}`);
        return await res.json();
    } finally {
        clearTimeout(timer);
    }
}

// Fast path for the background worker's onBeforeNavigate hook: ML + Safe
// Browsing only, no OSINT — should return in well under a second. Short
// timeout on purpose so a slow/unreachable backend fails fast instead of
// leaving the navigation hanging.
export async function predictFast(url, timeoutMs = 5000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const res = await fetch(`${API_BASE}/predict/fast`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
            signal: controller.signal,
        });
        if (!res.ok) throw new Error(`API error ${res.status}`);
        return await res.json();
    } finally {
        clearTimeout(timer);
    }
}

// Full OSINT investigation (WHOIS, cert transparency, reverse IP, etc).
// Slow — only called on demand from the warning page, not on every navigation.
export async function investigateURL(url, timeoutMs = 90000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const res = await fetch(`${API_BASE}/investigate`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
            signal: controller.signal,
        });
        if (!res.ok) throw new Error(`API error ${res.status}`);
        return await res.json();
    } finally {
        clearTimeout(timer);
    }
}

export async function checkHealth() {
    const res = await fetch(`${API_BASE}/health`);
    return res.ok;
}