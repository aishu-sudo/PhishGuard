import React, { useState } from 'react';
import { Search, ShieldAlert, ShieldCheck, AlertTriangle, Zap, Server, Lock, Globe, Cpu, ChevronRight, FileText, Activity } from 'lucide-react';
import { API_BASE_URL } from '../config';

export default function UrlScanner({ onScanComplete }) {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanMode, setScanMode] = useState('full'); // 'fast', 'full', 'investigate'
  const [result, setResult] = useState(null);
  const [investigationData, setInvestigationData] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async (targetUrl = urlInput, mode = scanMode) => {
    const finalUrl = (targetUrl || urlInput).trim();
    if (!finalUrl) return;

    setLoading(true);
    setError(null);
    setResult(null);
    setInvestigationData(null);

    try {
      if (mode === 'investigate') {
        const res = await fetch(`${API_BASE_URL}/investigate`, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'bypass-tunnel-reminder': 'true'
          },
          body: JSON.stringify({ url: finalUrl }),
        });
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        const data = await res.json();
        setInvestigationData(data);
        setResult({
          url: finalUrl,
          alert_level: data.verdict === 'HIGH_RISK' ? 'RED' : 'GREEN',
          fused_score: data.verdict === 'HIGH_RISK' ? 0.95 : 0.05,
          supervised_score: data.verdict === 'HIGH_RISK' ? 0.98 : 0.02,
          anomaly_score: data.verdict === 'HIGH_RISK' ? 0.90 : 0.10,
          threat_intel: data,
        });
      } else {
        const endpoint = mode === 'fast' ? '/predict/fast' : '/predict/url';
        const res = await fetch(`${API_BASE_URL}${endpoint}`, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'bypass-tunnel-reminder': 'true'
          },
          body: JSON.stringify({ url: finalUrl }),
        });
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        const data = await res.json();
        setResult(data);

        if (data.threat_intel) {
          setInvestigationData(data.threat_intel);
        }
        if (onScanComplete) {
          onScanComplete({ ...data, type: 'url', timestamp: new Date().toISOString() });
        }
      }
    } catch (err) {
      setError(err.message || 'Failed to connect to backend server');
    } finally {
      setLoading(false);
    }
  };

  const getAlertIcon = (level) => {
    if (level === 'RED') return <ShieldAlert size={32} />;
    if (level === 'YELLOW') return <AlertTriangle size={32} />;
    return <ShieldCheck size={32} />;
  };

  const getScoreColor = (score) => {
    if (score >= 0.65) return 'var(--color-danger)';
    if (score >= 0.40) return 'var(--color-warn)';
    return 'var(--color-safe)';
  };

  return (
    <div>
      {/* Scanner Box */}
      <div className="glass-panel scanner-card">
        <h2 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.25rem' }}>
          Analyze Web Link & OSINT Footprint
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Test any website URL against XGBoost classification, Isolation Forest anomaly scoring, and deep threat intelligence.
        </p>

        <div className="input-group">
          <input
            type="text"
            className="search-input"
            placeholder="Paste URL here (e.g. http://paypal-verify-login.xyz)..."
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleScan()}
          />
          <button
            className="btn-primary"
            disabled={loading || !urlInput.trim()}
            onClick={() => handleScan(urlInput, 'full')}
          >
            <Search size={18} />
            {loading ? 'Analyzing...' : 'Analyze URL'}
          </button>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
          <button
            className={`btn-secondary ${scanMode === 'full' ? 'active' : ''}`}
            onClick={() => {
              setScanMode('full');
              if (urlInput.trim()) handleScan(urlInput, 'full');
            }}
            style={{ fontSize: '0.825rem', padding: '0.5rem 1rem' }}
          >
            <Zap size={14} /> Full Scoring
          </button>
          <button
            className={`btn-secondary ${scanMode === 'fast' ? 'active' : ''}`}
            onClick={() => {
              setScanMode('fast');
              if (urlInput.trim()) handleScan(urlInput, 'fast');
            }}
            style={{ fontSize: '0.825rem', padding: '0.5rem 1rem' }}
          >
            <Activity size={14} /> Fast Mode (No OSINT)
          </button>
          <button
            className={`btn-secondary ${scanMode === 'investigate' ? 'active' : ''}`}
            onClick={() => {
              setScanMode('investigate');
              if (urlInput.trim()) handleScan(urlInput, 'investigate');
            }}
            style={{ fontSize: '0.825rem', padding: '0.5rem 1rem' }}
          >
            <Server size={14} /> Deep OSINT Investigation
          </button>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="glass-panel" style={{ padding: '1.25rem 1.5rem', marginBottom: '2rem', borderLeft: '4px solid var(--color-danger)' }}>
          <div style={{ color: 'var(--color-danger)', fontWeight: 700, marginBottom: '0.25rem' }}>Connection Error</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>{error}</div>
        </div>
      )}

      {/* Results View */}
      {result && (
        <div>
          {/* Main Alert Banner */}
          <div className={`alert-card ${result.alert_level}`}>
            <div className="alert-info">
              <div className="alert-icon-box">
                {getAlertIcon(result.alert_level)}
              </div>
              <div>
                <div className="alert-heading">
                  {result.alert_level === 'RED' && 'Dangerous Phishing Threat Detected'}
                  {result.alert_level === 'YELLOW' && 'Suspicious / Elevated Risk Website'}
                  {result.alert_level === 'GREEN' && 'Verified Safe Website'}
                </div>
                <div className="alert-desc">
                  {result.alert_level === 'RED' && 'PhishGuard ML has strong evidence this domain is mimicking a known brand or deploying phishing kits.'}
                  {result.alert_level === 'YELLOW' && 'This domain shows unusual structural patterns or brand-spoofing indicators.'}
                  {result.alert_level === 'GREEN' && 'No phishing or structural anomaly patterns detected.'}
                </div>
              </div>
            </div>

            <div className="score-badge-large">
              <div className="score-val" style={{ color: getScoreColor(result.fused_score || 0) }}>
                {Math.round((result.fused_score || 0) * 100)}%
              </div>
              <div className="score-lbl">Risk Score</div>
            </div>
          </div>

          {/* Model Breakdown Metric Cards */}
          <div className="grid-3">
            <div className="glass-panel metric-card">
              <div className="metric-header">
                <span className="metric-title">Fused Decision Risk</span>
                <Cpu size={18} style={{ color: 'var(--accent-cyan)' }} />
              </div>
              <div className="metric-number" style={{ color: getScoreColor(result.fused_score || 0) }}>
                {(result.fused_score || 0).toFixed(4)}
              </div>
              <div className="progress-bar-bg">
                <div
                  className="progress-bar-fill"
                  style={{
                    width: `${Math.min(100, (result.fused_score || 0) * 100)}%`,
                    backgroundColor: getScoreColor(result.fused_score || 0),
                  }}
                ></div>
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-header">
                <span className="metric-title">XGBoost Supervised Score</span>
                <Zap size={18} style={{ color: 'var(--accent-blue)' }} />
              </div>
              <div className="metric-number">
                {(result.supervised_score || 0).toFixed(4)}
              </div>
              <div className="progress-bar-bg">
                <div
                  className="progress-bar-fill"
                  style={{
                    width: `${Math.min(100, (result.supervised_score || 0) * 100)}%`,
                    backgroundColor: 'var(--accent-blue)',
                  }}
                ></div>
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-header">
                <span className="metric-title">Isolation Forest Anomaly Index</span>
                <Activity size={18} style={{ color: 'var(--accent-purple)' }} />
              </div>
              <div className="metric-number">
                {(result.anomaly_score || 0).toFixed(4)}
              </div>
              <div className="progress-bar-bg">
                <div
                  className="progress-bar-fill"
                  style={{
                    width: `${Math.min(100, (result.anomaly_score || 0) * 100)}%`,
                    backgroundColor: 'var(--accent-purple)',
                  }}
                ></div>
              </div>
            </div>
          </div>

          {/* Threat Intelligence / OSINT Cards */}
          {investigationData && (
            <div className="grid-2">
              {/* WHOIS & SSL Card */}
              <div className="glass-panel osint-card">
                <div className="osint-header">
                  <Lock size={20} style={{ color: 'var(--accent-cyan)' }} />
                  WHOIS & Security Credentials
                </div>
                <table className="data-table">
                  <tbody>
                    <tr>
                      <td className="data-label">Target Domain</td>
                      <td className="data-value">{investigationData.host || investigationData.domain || result.url}</td>
                    </tr>
                    <tr>
                      <td className="data-label">Registrar</td>
                      <td className="data-value">{investigationData.whois?.registrar || investigationData.whois?.error || 'N/A'}</td>
                    </tr>
                    <tr>
                      <td className="data-label">Creation Date</td>
                      <td className="data-value">{investigationData.whois?.creation_date || 'N/A'}</td>
                    </tr>
                    <tr>
                      <td className="data-label">Domain Age</td>
                      <td className="data-value">
                        {investigationData.whois?.domain_age_days ? `${investigationData.whois.domain_age_days} days` : 'N/A'}
                      </td>
                    </tr>
                    <tr>
                      <td className="data-label">SSL Issuer</td>
                      <td className="data-value">{investigationData.ssl?.issuer || investigationData.ssl?.error || 'N/A'}</td>
                    </tr>
                  </tbody>
                </table>
              </div>

              {/* Hosting & Network Card */}
              <div className="glass-panel osint-card">
                <div className="osint-header">
                  <Server size={20} style={{ color: 'var(--accent-blue)' }} />
                  IP & Infrastructure Footprint
                </div>
                <table className="data-table">
                  <tbody>
                    <tr>
                      <td className="data-label">IP Address</td>
                      <td className="data-value">{investigationData.ip?.ip || investigationData.ip?.ipv4?.[0] || 'N/A'}</td>
                    </tr>
                    <tr>
                      <td className="data-label">ASN / Hosting</td>
                      <td className="data-value">{investigationData.ip?.hosting || investigationData.ip?.asn || 'N/A'}</td>
                    </tr>
                    <tr>
                      <td className="data-label">Country</td>
                      <td className="data-value">{investigationData.ip?.country || 'N/A'}</td>
                    </tr>
                    <tr>
                      <td className="data-label">Safe Browsing</td>
                      <td className="data-value">
                        <span className={`tag-badge ${investigationData.safe_browsing?.flagged ? 'danger' : 'success'}`}>
                          {investigationData.safe_browsing?.flagged ? 'FLAGGED MALICIOUS' : 'CLEAN / PASSED'}
                        </span>
                      </td>
                    </tr>
                    <tr>
                      <td className="data-label">Threat Verdict</td>
                      <td className="data-value">
                        <span className={`tag-badge ${investigationData.verdict === 'HIGH_RISK' ? 'danger' : 'success'}`}>
                          {investigationData.verdict || (result.alert_level === 'RED' ? 'HIGH_RISK' : 'SAFE')}
                        </span>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
