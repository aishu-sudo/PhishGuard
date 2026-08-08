import React, { useState } from 'react';
import { MessageSquare, AlertTriangle, ShieldCheck, ShieldAlert, Sparkles, Send } from 'lucide-react';
import { API_BASE_URL } from '../config';

export default function TextAnalyzer({ onScanComplete }) {
  const [textInput, setTextInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleAnalyzeText = async (inputStr = textInput) => {
    const finalStr = (inputStr || textInput).trim();
    if (!finalStr) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch(`${API_BASE_URL}/predict/text`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: finalStr }),
      });

      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      const data = await res.json();
      setResult(data);

      if (onScanComplete) {
        onScanComplete({ ...data, type: 'text', textPreview: finalStr.slice(0, 60), timestamp: new Date().toISOString() });
      }
    } catch (err) {
      setError(err.message || 'Failed to analyze text snippet');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <div className="glass-panel scanner-card">
        <h2 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.25rem' }}>
          Analyze Email & Text Phishing Intent
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '1.25rem' }}>
          Test any email snippet, SMS message, or chat text against Transformer NLP classification and social engineering intent scoring.
        </p>

        <textarea
          className="text-analyzer-area"
          placeholder="Paste email text, SMS, or suspicious message content here..."
          value={textInput}
          onChange={(e) => setTextInput(e.target.value)}
        />

        <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', marginTop: '1rem' }}>
          <button
            className="btn-primary"
            disabled={loading || !textInput.trim()}
            onClick={() => handleAnalyzeText()}
          >
            <Sparkles size={18} />
            {loading ? 'Classifying...' : 'Classify Text'}
          </button>
        </div>
      </div>

      {error && (
        <div className="glass-panel" style={{ padding: '1.25rem 1.5rem', marginBottom: '2rem', borderLeft: '4px solid var(--color-danger)' }}>
          <div style={{ color: 'var(--color-danger)', fontWeight: 700, marginBottom: '0.25rem' }}>Classification Error</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>{error}</div>
        </div>
      )}

      {result && (
        <div>
          <div className={`alert-card ${result.label === 'PHISHING' ? 'RED' : 'GREEN'}`}>
            <div className="alert-info">
              <div className="alert-icon-box">
                {result.label === 'PHISHING' ? <ShieldAlert size={32} /> : <ShieldCheck size={32} />}
              </div>
              <div>
                <div className="alert-heading">
                  {result.label === 'PHISHING' ? 'Phishing / Social Engineering Intent Detected' : 'Legitimate Text Content'}
                </div>
                <div className="alert-desc">
                  {result.label === 'PHISHING'
                    ? 'The transformer NLP model detected deceptive patterns, fake urgency, credential harvesting language, or malicious call-to-actions.'
                    : 'The text passed NLP classification with no suspicious urgency or phishing patterns.'}
                </div>
              </div>
            </div>

            <div className="score-badge-large">
              <div className="score-val" style={{ color: result.label === 'PHISHING' ? 'var(--color-danger)' : 'var(--color-safe)' }}>
                {Math.round(result.phishing_probability * 100)}%
              </div>
              <div className="score-lbl">Phishing Prob</div>
            </div>
          </div>

          <div className="grid-2">
            <div className="glass-panel metric-card">
              <div className="metric-header">
                <span className="metric-title">Phishing Probability</span>
                <AlertTriangle size={18} style={{ color: 'var(--color-danger)' }} />
              </div>
              <div className="metric-number" style={{ color: 'var(--color-danger)' }}>
                {(result.phishing_probability * 100).toFixed(2)}%
              </div>
              <div className="progress-bar-bg">
                <div
                  className="progress-bar-fill"
                  style={{
                    width: `${result.phishing_probability * 100}%`,
                    backgroundColor: 'var(--color-danger)',
                  }}
                ></div>
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-header">
                <span className="metric-title">Legitimate Probability</span>
                <ShieldCheck size={18} style={{ color: 'var(--color-safe)' }} />
              </div>
              <div className="metric-number" style={{ color: 'var(--color-safe)' }}>
                {(result.legitimate_probability * 100).toFixed(2)}%
              </div>
              <div className="progress-bar-bg">
                <div
                  className="progress-bar-fill"
                  style={{
                    width: `${result.legitimate_probability * 100}%`,
                    backgroundColor: 'var(--color-safe)',
                  }}
                ></div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
