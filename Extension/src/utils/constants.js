export const API_BASE = "https://cinema-sacred-resorts-continuously.trycloudflare.com";
export const RED_THRESHOLD = 0.65;
export const YELLOW_THRESHOLD = 0.40;

export const ALERT_CONFIG = {
    RED: { label: "DANGEROUS", emoji: "🚨", color: "#dc2626", bg: "#fef2f2", border: "#fecaca" },
    YELLOW: { label: "SUSPICIOUS", emoji: "⚠️", color: "#d97706", bg: "#fffbeb", border: "#fde68a" },
    GREEN: { label: "SAFE", emoji: "✅", color: "#16a34a", bg: "#f0fdf4", border: "#bbf7d0" },
};