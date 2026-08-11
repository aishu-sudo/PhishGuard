const TUNNEL_URL = 'https://gif-trainer-protein-retrieve.trycloudflare.com';
const LOCAL_URL = 'http://127.0.0.1:8000';

export const API_BASE_URL = TUNNEL_URL;

export async function safeFetch(endpoint, options = {}) {
  const urls = [TUNNEL_URL, LOCAL_URL];
  let lastErr;
  for (const base of urls) {
    try {
      const res = await fetch(`${base}${endpoint}`, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...(options.headers || {}),
        },
      });
      if (res.ok) return res;
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error('All backend connections failed');
}
