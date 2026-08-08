// PhishGuard API Configuration
// Can be overridden by VITE_API_URL environment variable in production cloud deployment
export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';
