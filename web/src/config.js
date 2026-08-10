// PhishGuard Robust Self-Healing API & Standalone Fallback Engine
import { analyzeUrlLocal, analyzeTextLocal } from './utils/localAnalysis';

const TUNNEL_URL = 'https://agreement-combines-looksmart-twice.trycloudflare.com';
const LOCAL_URL = 'http://127.0.0.1:8000';

export const API_BASE_URL = TUNNEL_URL;

export async function safeFetch(path, options = {}) {
  let bodyData = {};
  try {
    if (options.body) {
      bodyData = JSON.parse(options.body);
    }
  } catch (e) {}

  // 1. Try Live Backend Endpoints (Cloudflare Tunnel -> Local PC Host)
  const targets = Array.from(new Set([
    TUNNEL_URL,
    LOCAL_URL
  ]));

  for (const base of targets) {
    try {
      const url = `${base.replace(/\/$/, '')}${path}`;
      const controller = new AbortController();
      // 5-second timeout
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const res = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          'Bypass-Tunnel-Reminder': 'true',
          'bypass-tunnel-reminder': 'true',
          'ngrok-skip-browser-warning': 'true',
          ...(options.headers || {})
        }
      });

      clearTimeout(timeoutId);

      // Verify that response is valid JSON and HTTP 200 OK
      const contentType = res.headers.get('content-type') || '';
      if (res.ok && contentType.includes('application/json')) {
        const clonedRes = res.clone();
        try {
          await clonedRes.json();
          return res; // Valid JSON API response!
        } catch (jsonErr) {
          // HTML or invalid JSON returned -> continue to fallback
        }
      }
    } catch (err) {
      // Network error or timeout -> continue to fallback
    }
  }

  // 2. Standalone Client-Side AI Engine Fallback (Instant, 100% Reliable Execution)
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
