// PhishGuard Robust API Configuration & Self-Healing Endpoint Resolver
const CURRENT_ACTIVE_TUNNEL = 'https://silence-membership-clause-handed.trycloudflare.com';
const LOCAL_URL = 'http://127.0.0.1:8000';

export const API_BASE_URL = CURRENT_ACTIVE_TUNNEL;

export async function safeFetch(path, options = {}) {
  let lastError = null;

  // Get cached working endpoint if available
  const cachedEndpoint = typeof window !== 'undefined' ? localStorage.getItem('phishguard_active_api') : null;

  // Priority order: Cached Working Endpoint -> Active Tunnel -> Local PC Host
  const targets = Array.from(new Set([
    cachedEndpoint,
    CURRENT_ACTIVE_TUNNEL,
    LOCAL_URL
  ].filter(Boolean)));

  for (const base of targets) {
    try {
      const url = `${base.replace(/\/$/, '')}${path}`;
      const controller = new AbortController();
      // 30 second timeout for WHOIS & SSL lookups
      const timeoutId = setTimeout(() => controller.abort(), 30000);

      const res = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          'bypass-tunnel-reminder': 'true',
          'ngrok-skip-browser-warning': 'true',
          ...(options.headers || {})
        }
      });

      clearTimeout(timeoutId);

      if (res.ok) {
        // Cache working endpoint for instant subsequent requests
        if (typeof window !== 'undefined') {
          localStorage.setItem('phishguard_active_api', base);
        }
        return res;
      }
      lastError = new Error(`HTTP error ${res.status}`);
    } catch (err) {
      lastError = err;
    }
  }

  // If cached endpoint failed, clear it for next attempt
  if (typeof window !== 'undefined') {
    localStorage.removeItem('phishguard_active_api');
  }

  throw lastError || new Error('Failed to fetch from local PC backend');
}
