// PhishGuard API Configuration (Local PC Host via Active Cloudflare Tunnel)
const TUNNEL_URL = 'https://silence-membership-clause-handed.trycloudflare.com';
const LOCAL_URL = 'http://127.0.0.1:8000';

export const API_BASE_URL = TUNNEL_URL;

export async function safeFetch(path, options = {}) {
  let lastError = null;
  // Always try live active tunnel first, then local PC host
  const targets = Array.from(new Set([
    TUNNEL_URL,
    LOCAL_URL
  ]));

  for (const base of targets) {
    try {
      const url = `${base.replace(/\/$/, '')}${path}`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 20000);

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

  throw lastError || new Error('Failed to connect to backend server');
}
