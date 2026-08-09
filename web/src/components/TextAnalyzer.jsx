import React, { useState } from 'react';
import { MessageSquare, AlertTriangle, ShieldCheck, ShieldAlert, Sparkles, Send } from 'lucide-react';
import { safeFetch } from '../config';

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
      const res = await safeFetch('/predict/text', {
        method: 'POST',
        body: JSON.stringify({ text: finalStr }),
      });

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

  const runSampleText = (sampleText) => {
    setTextInput(sampleText);
    handleAnalyzeText(sampleText);
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

        {/* 1-Click Samples */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.75rem' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>Quick Samples:</span>
          <button
            type="button"
            className="btn-secondary"
            style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem', borderRadius: '4px', borderColor: 'rgba(239, 68, 68, 0.3)', color: '#f87171' }}
            onClick={() => runSampleText('URGENT: Your bank account password has expired. Click here immediately to verify your credentials or your account will be permanently suspended within 24 hours.')}
          >
            🚨 Phishing SMS Sample
          </button>
          <button
            type="button"
            className="btn-secondary"
            style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem', borderRadius: '4px', borderColor: 'rgba(34, 197, 94, 0.3)', color: '#4ade80' }}
            onClick={() => runSampleText('Hi John, here is the weekly team project update meeting summary for your review. Let me know if you have any questions.')}
          >
            ✅ Safe Email Sample
          </button>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', marginTop: '1rem' }}>
          <button
            className="btn-primary"
            disabled={loading || !textInput.trim()}
            onClick={() => handleAnalyzeText(textInput)}
          >
            <Send size={18} />
            {loading ? 'Analyzing Intent...' : 'Analyze Message'}
          </button>
        </div>
      </div>

      {error && (
        <div className="glass-panel" style={{ marginTop: '1.5rem', borderColor: 'var(--color-danger)', color: 'var(--color-danger)' }}>
          <h4 style={{ fontWeight: 700, marginBottom: '0.25rem' }}>Text Analysis Error</h4>
          <p style={{ fontSize: '0.9rem' }}>{error}</p>
        </div>
      )}

      {loading && (
        <div className="glass-panel" style={{ marginTop: '1.5rem', textAlign: 'center', padding: '2.5rem' }}>
          <div className="pulse-dot" style={{ width: '16px', height: '16px', margin: '0 auto 1rem' }}></div>
          <h3 style={{ fontWeight: 700, fontSize: '1.1rem' }}>Evaluating Social Engineering Intent...</h3>
        </div>
      )}

      {result && !loading && (
        <div style={{ marginTop: '1.5rem' }}>
          <div className={`glass-panel risk-banner risk-${result.label === 'PHISHING' ? 'red' : 'green'}`}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <div className="alert-icon-wrapper">
                {result.label === 'PHISHING' ? <ShieldAlert size={32} /> : <ShieldCheck size={32} />}
              </div>
              <div>
                <span className="badge-level">{result.label}</span>
                <h3 style={{ fontSize: '1.4rem', fontWeight: 800, marginTop: '0.25rem' }}>
                  {result.label === 'PHISHING' ? 'Phishing & Credential Theft Risk Detected' : 'Safe Legitimate Communication'}
                </h3>
                <p style={{ fontSize: '0.9rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                  Intent: {result.intent || 'Message Analysis'}
                </p>
              </div>
            </div>

            <div className="metrics-grid" style={{ marginTop: '1.5rem', paddingTop: '1.5rem', borderTop: '1px solid var(--border-subtle)' }}>
              <div className="metric-box">
                <span className="metric-title"><Sparkles size={14} /> Phishing Probability</span>
                <span className="metric-value" style={{ color: result.label === 'PHISHING' ? 'var(--color-danger)' : 'var(--color-safe)' }}>
                  {((result.phishing_probability || 0) * 100).toFixed(1)}%
                </span>
              </div>
              <div className="metric-box">
                <span className="metric-title"><MessageSquare size={14} /> Classification Confidence</span>
                <span className="metric-value" style={{ color: 'var(--accent-cyan)' }}>
                  {((result.confidence || 0) * 100).toFixed(1)}%
                </span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
