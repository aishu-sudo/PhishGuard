import React from 'react';
import { History, Trash2, Globe, MessageSquare, ExternalLink } from 'lucide-react';

export default function ScanHistory({ history, onClearHistory }) {
  if (!history || history.length === 0) {
    return (
      <div className="glass-panel" style={{ padding: '3rem', textAlign: 'center' }}>
        <History size={48} style={{ color: 'var(--text-dim)', marginBottom: '1rem' }} />
        <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.5rem' }}>No Scan History Yet</h3>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Analyze a URL or email snippet using the scanner tabs above. Your history will be recorded locally.
        </p>
      </div>
    );
  }

  return (
    <div className="glass-panel" style={{ padding: '2rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#ffffff' }}>Recent Analysis History</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Stored locally in browser session ({history.length} scans)</p>
        </div>

        <button className="btn-secondary" onClick={onClearHistory} style={{ color: 'var(--color-danger)', borderColor: 'rgba(239, 68, 68, 0.3)' }}>
          <Trash2 size={16} /> Clear History
        </button>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {history.map((item, idx) => {
          const isUrl = item.type === 'url';
          const alertClass = item.alert_level || (item.label === 'PHISHING' ? 'RED' : 'GREEN');
          
          return (
            <div
              key={idx}
              className="glass-panel"
              style={{
                padding: '1rem 1.25rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                borderLeft: `4px solid ${
                  alertClass === 'RED' ? 'var(--color-danger)' : alertClass === 'YELLOW' ? 'var(--color-warn)' : 'var(--color-safe)'
                }`,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <div
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: 8,
                    background: 'rgba(255, 255, 255, 0.05)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: isUrl ? 'var(--accent-cyan)' : 'var(--accent-purple)',
                  }}
                >
                  {isUrl ? <Globe size={18} /> : <MessageSquare size={18} />}
                </div>

                <div>
                  <div style={{ fontFamily: isUrl ? 'var(--font-mono)' : 'var(--font-sans)', fontWeight: 600, fontSize: '0.9rem', color: '#ffffff' }}>
                    {isUrl ? item.url : `"${item.textPreview}..."`}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
                    {new Date(item.timestamp).toLocaleString()} • {isUrl ? 'URL Scan' : 'Text NLP Scan'}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <span className={`tag-badge ${alertClass === 'RED' ? 'danger' : alertClass === 'YELLOW' ? 'warn' : 'success'}`}>
                  {alertClass === 'RED' ? 'PHISHING / HIGH RISK' : alertClass === 'YELLOW' ? 'SUSPICIOUS' : 'SAFE'}
                </span>
                {isUrl && (
                  <a
                    href={item.url}
                    target="_blank"
                    rel="noreferrer"
                    style={{ color: 'var(--text-muted)', textDecoration: 'none' }}
                  >
                    <ExternalLink size={16} />
                  </a>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
