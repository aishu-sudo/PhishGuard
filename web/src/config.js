// PhishGuard Self-Healing API & Standalone Engine Config
import { analyzeUrlLocal, analyzeTextLocal } from './utils/localAnalysis';

export const API_BASE_URL = 'https://tiger-shaft-resumes-willow.trycloudflare.com';

export async function safeFetch(path, options = {}) {
  let bodyData = {};
  try {
    if (options.body) {
      bodyData = JSON.parse(options.body);
    }
  } catch (e) {}

  // Try Remote Cloud/Local Backend first with a fast 3s timeout
  try {
    const url = `${API_BASE_URL.replace(/\/$/, '')}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);

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
    // Remote connection failed or timed out — fallback seamlessly to standalone client engine
  }

  // Standalone Client-Side AI Engine Fallback Execution
  let mockData;
  if (path === '/health') {
    mockData = { status: 'ok', service: 'PhishGuard Standalone AI Engine' };
  } else if (path === '/predict/fast' || path === '/predict/url' || path === '/investigate') {
    mockData = analyzeUrlLocal(bodyData.url || '');
  } else if (path === '/predict/text') {
    mockData = analyzeTextLocal(bodyData.text || '');
  } else {
    mockData = { status: 'ok' };
  }

  // Return synthetic Response object with HTTP 200 OK
  return new Response(JSON.stringify(mockData), {
    status: 200,
    statusText: 'OK',
    headers: { 'Content-Type': 'application/json' }
  });
}
