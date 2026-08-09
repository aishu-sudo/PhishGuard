// PhishGuard Robust API Configuration (Multi-Cloud HTTPS Fallback)
const CLOUDFLARE_TUNNEL_URL = 'https://tiger-shaft-resumes-willow.trycloudflare.com';
const RENDER_CLOUD_URL = 'https://phishguard-rl19.onrender.com';

export const API_BASE_URL = CLOUDFLARE_TUNNEL_URL;

export async function safeFetch(path, options = {}) {
  let lastError = null;

  // Pure HTTPS targets to guarantee zero Mixed Content security blocks in browsers
  const targets = Array.from(new Set([
    CLOUDFLARE_TUNNEL_URL,
    RENDER_CLOUD_URL
  ].filter(Boolean)));

  for (const base of targets) {
    try {
      const url = `${base.replace(/\/$/, '')}${path}`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 25000);

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

  throw lastError || new Error('Failed to connect to PhishGuard backend service');
}
