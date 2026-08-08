import { useState } from "react";
import { useTabState } from "./hooks/useTabState";
import { ALERT_CONFIG } from "../utils/constants";

const styles = {
  wrap: {
    width: 340,
    fontFamily: "'Segoe UI', sans-serif",
    fontSize: 14,
    color: "#1e293b",
    background: "#ffffff",
  },
  header: {
    background: "#1e293b",
    color: "#fff",
    padding: "12px 16px",
    display: "flex",
    alignItems: "center",
    gap: 8,
  },
  logo: { fontSize: 20 },
  title: { fontWeight: 700, fontSize: 16, letterSpacing: 0.5 },
  offline: {
    background: "#fef2f2",
    color: "#dc2626",
    padding: "8px 16px",
    fontSize: 12,
    borderBottom: "1px solid #fecaca",
  },
  body: { padding: 16 },
  urlBox: {
    background: "#f8fafc",
    border: "1px solid #e2e8f0",
    borderRadius: 6,
    padding: "8px 10px",
    fontSize: 11,
    color: "#475569",
    wordBreak: "break-all",
    marginBottom: 12,
    maxHeight: 48,
    overflow: "hidden",
  },
  resultCard: (cfg) => ({
    background: cfg.bg,
    border: `2px solid ${cfg.border}`,
    borderRadius: 10,
    padding: 16,
    textAlign: "center",
    marginBottom: 12,
  }),
  alertLabel: (cfg) => ({
    fontSize: 20,
    fontWeight: 800,
    color: cfg.color,
    marginBottom: 4,
  }),
  scoreRow: {
    display: "flex",
    justifyContent: "space-around",
    marginTop: 10,
    fontSize: 12,
    color: "#475569",
  },
  scoreItem: { textAlign: "center" },
  scoreValue: { fontWeight: 700, fontSize: 15, color: "#1e293b" },
  bar: (fused) => ({
    height: 8,
    borderRadius: 4,
    marginTop: 10,
    background: `linear-gradient(to right,
      #16a34a ${Math.round((1 - fused) * 100)}%,
      #dc2626 100%)`,
  }),
  spinner: {
    textAlign: "center",
    padding: 24,
    color: "#64748b",
    fontSize: 13,
  },
  errorBox: {
    background: "#fef2f2",
    color: "#dc2626",
    borderRadius: 6,
    padding: 10,
    fontSize: 12,
    marginBottom: 10,
  },
  manualRow: {
    display: "flex",
    gap: 6,
    marginTop: 4,
  },
  input: {
    flex: 1,
    border: "1px solid #cbd5e1",
    borderRadius: 6,
    padding: "6px 8px",
    fontSize: 12,
    outline: "none",
  },
  btn: {
    background: "#1e293b",
    color: "#fff",
    border: "none",
    borderRadius: 6,
    padding: "6px 12px",
    cursor: "pointer",
    fontSize: 12,
  },
  detailsRow: {
    display: "flex",
    justifyContent: "space-between",
    fontSize: 11,
    padding: "2px 0",
    color: "#475569",
  },
};

function ScoreBar({ score }) {
  const pct = Math.round(score * 100);
  return (
    <div style={{ marginTop: 8 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "#64748b" }}>
        <span>Safe</span>
        <span>Risk: {pct}%</span>
        <span>Danger</span>
      </div>
      <div style={{ height: 8, background: "#e2e8f0", borderRadius: 4, marginTop: 3 }}>
        <div style={{
          width: `${pct}%`,
          height: "100%",
          borderRadius: 4,
          background: score >= 0.65 ? "#dc2626" : score >= 0.40 ? "#f59e0b" : "#16a34a",
          transition: "width 0.4s ease",
        }} />
      </div>
    </div>
  );
}

function ThreatIntelDetails({ ti }) {
  if (!ti) return null;

  const whois = ti.whois || {};
  const ip = ti.ip || {};
  const sb = ti.safe_browsing || {};
  const vt = ti.virustotal || {};
  const cluster = ti.infrastructure_cluster || {};
  const cert = cluster.certificate_transparency || {};
  const subEnum = cluster.subdomain_discovery || {};
  const aliveCount = subEnum.alive_check?.alive?.length ?? 0;

  return (
    <div style={{ marginTop: 12, textAlign: "left", background: "#f8fafc", border: "1px solid #e2e8f0", borderRadius: 8, padding: 10, fontSize: 11 }}>
      <div style={{ fontWeight: 700, marginBottom: 6, color: "#1e293b" }}>Investigation Details</div>

      <div style={styles.detailsRow}><span>Registrar</span><span>{whois.registrar || "—"}</span></div>
      <div style={styles.detailsRow}><span>Domain age (days)</span><span>{whois.age_days ?? "—"}</span></div>
      <div style={styles.detailsRow}><span>Privacy protected</span><span>{whois.privacy_protected ? "Yes" : "No"}</span></div>
      <div style={styles.detailsRow}><span>Hosting</span><span>{ip.hosting || "—"}</span></div>
      <div style={styles.detailsRow}><span>Country</span><span>{ip.country || "—"}</span></div>

      <div style={styles.detailsRow}>
        <span>Safe Browsing</span>
        <span style={{ color: sb.flagged ? "#dc2626" : "#16a34a", fontWeight: 700 }}>
          {sb.flagged ? "FLAGGED" : sb.status === "ok" ? "Clean" : (sb.status || "unknown")}
        </span>
      </div>

      <div style={styles.detailsRow}>
        <span>VirusTotal</span>
        <span>{vt.malicious !== undefined ? `${vt.malicious} malicious` : (vt.status || "unknown")}</span>
      </div>

      <div style={styles.detailsRow}>
        <span>Shares cert w/ other domains</span>
        <span style={{ color: cert.related ? "#dc2626" : "#475569", fontWeight: cert.related ? 700 : 400 }}>
          {cert.related ? `Yes (${cert.related_domains?.length ?? 0})` : "No"}
        </span>
      </div>

      <div style={styles.detailsRow}>
        <span>Live subdomains found</span>
        <span style={{ color: aliveCount > 0 ? "#dc2626" : "#475569", fontWeight: aliveCount > 0 ? 700 : 400 }}>
          {subEnum.subfinder?.status === "tool_not_found" ? "Tool not installed" : aliveCount}
        </span>
      </div>
    </div>
  );
}

export default function App() {
  const { tabUrl, result, loading, error, apiOnline, analyzeUrl } = useTabState();
  const [manualUrl, setManualUrl] = useState("");

  const cfg = result ? ALERT_CONFIG[result.alert_level] : null;

  function handleManualCheck() {
    const url = manualUrl.trim();
    if (url) analyzeUrl(url.startsWith("http") ? url : "https://" + url);
  }

  return (
    <div style={styles.wrap}>
      <div style={styles.header}>
        <span style={styles.logo}>🛡️</span>
        <span style={styles.title}>PhishGuard</span>
      </div>

      {!apiOnline && (
        <div style={styles.offline}>
          ⚡ Backend offline — run: <code>uvicorn main:app --port 8000</code>
        </div>
      )}

      <div style={styles.body}>
        {tabUrl && (
          <div style={styles.urlBox} title={tabUrl}>
            {tabUrl}
          </div>
        )}

        {loading && (
          <div style={styles.spinner}>Analyzing URL...</div>
        )}

        {error && (
          <div style={styles.errorBox}>
            Could not reach backend.<br />
            Make sure the API is running on port 8000.
          </div>
        )}

        {!loading && result && cfg && (
          <div style={styles.resultCard(cfg)}>
            <div style={{ fontSize: 28 }}>{cfg.emoji}</div>
            <div style={styles.alertLabel(cfg)}>{cfg.label}</div>
            <ScoreBar score={result.fused_score} />
            <div style={styles.scoreRow}>
              <div style={styles.scoreItem}>
                <div style={styles.scoreValue}>{Math.round(result.supervised_score * 100)}%</div>
                <div>XGBoost</div>
              </div>
              <div style={styles.scoreItem}>
                <div style={styles.scoreValue}>{Math.round(result.anomaly_score * 100)}%</div>
                <div>Anomaly</div>
              </div>
              <div style={styles.scoreItem}>
                <div style={styles.scoreValue}>{Math.round(result.fused_score * 100)}%</div>
                <div>Fused</div>
              </div>
            </div>
            <ThreatIntelDetails ti={result.threat_intel} />
          </div>
        )}

        <div style={styles.manualRow}>
          <input
            style={styles.input}
            placeholder="Check any URL..."
            value={manualUrl}
            onChange={(e) => setManualUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleManualCheck()}
          />
          <button style={styles.btn} onClick={handleManualCheck}>Check</button>
        </div>
      </div>
    </div>
  );
}