// PhishGuard API Configuration (Local PC Host via Cloudflare Tunnel)
import { analyzeUrlLocal, analyzeTextLocal } from './utils/localAnalysis';

const TUNNEL_URL = 'https://tiger-shaft-resumes-willow.trycloudflare.com';
const LOCAL_URL = 'http://127.0.0.1:8000';

export const API_BASE_URL = TUNNEL_URL;

export async function safeFetch(path, options = {}) {
  let bodyData = {};
  try {
    if (options.body) {
      bodyData = JSON.parse(options.body);
    }
  } catch (e) {}

  // Primary: Local PC Host via Cloudflare Tunnel
  const targets = Array.from(new Set([
    TUNNEL_URL,
    LOCAL_URL
  ]));

  for (const base of targets) {
    try {
      const url = `${base.replace(/\/$/, '')}${path}`;
      const controller = new AbortController();
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
    } catch (err) {
      // Continue to next target or fallback
    }
  }

  // Backup: Local Client-Side AI Engine Fallback if tunnel is temporarily unreachable
  let fallbackData;
  if (path === '/health') {
    fallbackData = { status: 'ok', service: 'PhishGuard Local Engine' };
  } else if (path === '/predict/fast' || path === '/predict/url' || path === '/investigate') {
    fallbackData = analyzeUrlLocal(bodyData.url || '');
  } else if (path === '/predict/text') {
    fallbackData = analyzeTextLocal(bodyData.text || '');
  } else {
    fallbackData = { status: 'ok' };
  }

  return new Response(JSON.stringify(fallbackData), {
    status: 200,
    statusText: 'OK',
    headers: { 'Content-Type': 'application/json' }
  });
}
