// PhishGuard API Configuration (Local PC Host via Cloudflare Tunnel)
const TUNNEL_URL = 'https://dawn-nightlife-foster-workout.trycloudflare.com';
const LOCAL_URL = 'http://127.0.0.1:8000';

export const API_BASE_URL = TUNNEL_URL;

export async function safeFetch(path, options = {}) {
  let lastError = null;
  // Strictly Local PC Host: Cloudflare Tunnel -> Local PC Host
  const targets = Array.from(new Set([
    TUNNEL_URL,
    LOCAL_URL
  ]));

  for (const base of targets) {
    try {
      const url = `${base.replace(/\/$/, '')}${path}`;
      const controller = new AbortController();
      // 30 second timeout to allow complete WHOIS & OSINT socket lookups
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
        return res;
      }
      lastError = new Error(`HTTP error ${res.status}`);
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError || new Error('Failed to fetch from local PC backend');
}
