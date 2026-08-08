// PhishGuard Cloud API Configuration
export const API_BASE_URL = import.meta.env.VITE_API_URL || 'https://phishguard-rl19.onrender.com';

export async function safeFetch(path, options = {}) {
  const url = `${API_BASE_URL.replace(/\/$/, '')}${path}`;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30000);

  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {})
      }
    });

    clearTimeout(timeoutId);
    if (!res.ok) {
      throw new Error(`HTTP error ${res.status}`);
    }
    return res;
  } catch (err) {
    clearTimeout(timeoutId);
    throw err;
  }
}
