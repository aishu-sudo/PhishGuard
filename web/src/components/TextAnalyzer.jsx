import React, { useState } from 'react';
import { AlertTriangle, ShieldCheck, ShieldAlert, Sparkles } from 'lucide-react';
import { safeFetch } from '../config';
import { analyzeTextLocal } from '../utils/localAnalysis';

export default function TextAnalyzer({ onScanComplete }) {
  const [textInput, setTextInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const handleAnalyzeText = async (inputStr = textInput) => {
    const finalStr = (inputStr || textInput).trim();
    if (!finalStr) return;

    setLoading(true);
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
      const localRes = analyzeTextLocal(finalStr);
      setResult(localRes);
      if (onScanComplete) {
        onScanComplete({ ...localRes, type: 'text', textPreview: finalStr.slice(0, 60), timestamp: new Date().toISOString() });
      }
    } finally {
      setLoading(false);
    }
  };

  // Score calculations
  const phishingProb = result ? (
    result.phishing_probability !== undefined
      ? result.phishing_probability
      : (result.label === 'PHISHING' ? (result.confidence || 0.99) : (1 - (result.confidence || 0.99)))
  ) : 0;
  const legitimateProb = 1 - phishingProb;

  const isPhishing = result ? (result.label === 'PHISHING' || phishingProb >= 0.50) : false;

  return (
    <div>
      <div className="glass-panel scanner-card">
        <h2 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.25rem' }}>
          Analyze Email & Text Phishing Intent
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: '1.25rem' }}>
          Test any email snippet, SMS message, or chat text against transformer NLP classification and social engineering intent scoring.
        </p>

        <textarea
          className="text-analyzer-area"
          style={{
            width: '100%',
            minHeight: '140px',
            backgroundColor: '#0b0f19',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            borderRadius: '8px',
            padding: '1rem',
            color: '#f3f4f6',
            fontSize: '0.95rem',
            fontFamily: 'inherit',
            resize: 'vertical',
            outline: 'none'
          }}
          placeholder="Paste email text, SMS, or suspicious message content here..."
          value={textInput}
          onChange={(e) => setTextInput(e.target.value)}
        />

        <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', marginTop: '1rem' }}>
          <button
            className="btn-primary"
            disabled={loading || !textInput.trim()}
            onClick={() => handleAnalyzeText(textInput)}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.5rem',
              background: 'linear-gradient(135deg, #06b6d4, #3b82f6)',
              color: '#ffffff',
              border: 'none',
              padding: '0.65rem 1.5rem',
              borderRadius: '8px',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            <Sparkles size={18} />
            {loading ? 'Classifying...' : 'Classify Text'}
          </button>
        </div>
      </div>

      {loading && (
        <div className="glass-panel" style={{ marginTop: '1.5rem', textAlign: 'center', padding: '2.5rem' }}>
          <div className="pulse-dot" style={{ width: '16px', height: '16px', margin: '0 auto 1rem' }}></div>
          <h3 style={{ fontWeight: 700, fontSize: '1.1rem' }}>Evaluating Social Engineering Intent...</h3>
        </div>
      )}

      {/* Cyber Dark Result Layout matching user screenshot */}
      {result && !loading && (
        <div style={{ marginTop: '1.5rem' }}>
          {/* Main Threat Banner */}
          <div className={`alert-card ${isPhishing ? 'RED' : 'GREEN'}`}>
            <div className="alert-info">
              <div className="alert-icon-box">
                {isPhishing ? <ShieldAlert size={36} /> : <ShieldCheck size={36} />}
              </div>
              <div>
                <div className="alert-heading">
                  {isPhishing ? 'Phishing / Social Engineering Intent Detected' : 'Safe / Legitimate Text Message'}
                </div>
                <div className="alert-desc">
                  {isPhishing
                    ? 'The transformer NLP model detected deceptive patterns, fake urgency, credential harvesting language, or malicious call-to-actions.'
                    : 'The transformer NLP model found no deceptive language or credential harvesting triggers.'}
                </div>
              </div>
            </div>

            <div className="score-badge-large">
              <div className="score-val" style={{ color: isPhishing ? '#ef4444' : '#22c55e' }}>
                {Math.round(phishingProb * 100)}%
              </div>
              <div className="score-lbl">PHISHING PROB</div>
            </div>
          </div>

          {/* 2 Metric Probability Cards */}
          <div className="grid-2" style={{ marginTop: '1rem' }}>
            {/* Phishing Probability Card */}
            <div className="glass-panel metric-card">
              <div className="metric-header">
                <span className="metric-title">PHISHING PROBABILITY</span>
                <AlertTriangle size={18} style={{ color: '#ef4444' }} />
              </div>
              <div className="metric-number" style={{ color: '#ef4444' }}>
                {(phishingProb * 100).toFixed(2)}%
              </div>
              <div className="progress-bar-bg">
                <div
                  className="progress-bar-fill"
                  style={{
                    width: `${Math.min(100, phishingProb * 100)}%`,
                    backgroundColor: '#ef4444',
                  }}
                ></div>
              </div>
            </div>

            {/* Legitimate Probability Card */}
            <div className="glass-panel metric-card">
              <div className="metric-header">
                <span className="metric-title">LEGITIMATE PROBABILITY</span>
                <ShieldCheck size={18} style={{ color: '#22c55e' }} />
              </div>
              <div className="metric-number" style={{ color: '#22c55e' }}>
                {(legitimateProb * 100).toFixed(2)}%
              </div>
              <div className="progress-bar-bg">
                <div
                  className="progress-bar-fill"
                  style={{
                    width: `${Math.min(100, legitimateProb * 100)}%`,
                    backgroundColor: '#22c55e',
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
