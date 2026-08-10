import { API_BASE, LOCAL_API_BASE } from "../utils/constants";

async function fetchWithFallback(endpoint, options, timeoutMs = 5000) {
    const targets = [API_BASE, LOCAL_API_BASE];
    let lastError = null;

    for (const base of targets) {
        if (!base) continue;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);

        try {
            const res = await fetch(`${base}${endpoint}`, {
                ...options,
                headers: { "Content-Type": "application/json", ...(options.headers || {}) },
                signal: controller.signal,
            });
            if (res.ok) {
                return await res.json();
            }
        } catch (err) {
            lastError = err;
        } finally {
            clearTimeout(timer);
        }
    }
    throw lastError || new Error(`API call failed for ${endpoint}`);
}

export async function predictURL(url, timeoutMs = 90000) {
    return fetchWithFallback("/predict/url", {
        method: "POST",
        body: JSON.stringify({ url }),
    }, timeoutMs);
}

export async function predictFast(url, timeoutMs = 5000) {
    return fetchWithFallback("/predict/fast", {
        method: "POST",
        body: JSON.stringify({ url }),
    }, timeoutMs);
}

export async function investigateURL(url, timeoutMs = 90000) {
    return fetchWithFallback("/investigate", {
        method: "POST",
        body: JSON.stringify({ url }),
    }, timeoutMs);
}

export async function checkHealth() {
    try {
        await fetchWithFallback("/health", { method: "GET" }, 3000);
        return true;
    } catch {
        return false;
    }
}