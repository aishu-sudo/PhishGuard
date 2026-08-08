import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import UrlScanner from './components/UrlScanner';
import TextAnalyzer from './components/TextAnalyzer';
import ScanHistory from './components/ScanHistory';
import { safeFetch } from './config';

export default function App() {
  const [activeTab, setActiveTab] = useState('url'); // 'url', 'text', 'history'
  const [apiStatus, setApiStatus] = useState('checking'); // 'connected', 'disconnected'
  const [history, setHistory] = useState([]);

  // Check Backend Server Health
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await safeFetch('/health');
        if (res.ok) {
          setApiStatus('connected');
        } else {
          setApiStatus('disconnected');
        }
      } catch (e) {
        setApiStatus('disconnected');
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 12000);
    return () => clearInterval(interval);
  }, []);

  // Load history from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem('phishguard_history');
      if (saved) {
        setHistory(JSON.parse(saved));
      }
    } catch (e) {}
  }, []);

  const handleScanComplete = (item) => {
    setHistory((prev) => {
      const updated = [item, ...prev].slice(0, 50);
      try {
        localStorage.setItem('phishguard_history', JSON.stringify(updated));
      } catch (e) {}
      return updated;
    });
  };

  const handleClearHistory = () => {
    setHistory([]);
    try {
      localStorage.removeItem('phishguard_history');
    } catch (e) {}
  };

  return (
    <div>
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} apiStatus={apiStatus} />

      <main className="main-wrapper">
        <div className="hero-banner">
          <h1 className="hero-title">Real-Time AI Phishing Intelligence</h1>
          <p className="hero-subtitle">
            Analyze suspicious web links, investigate domain infrastructure, and classify email/SMS text with XGBoost, Isolation Forest & Transformer NLP models.
          </p>
        </div>

        {activeTab === 'url' && <UrlScanner onScanComplete={handleScanComplete} />}
        {activeTab === 'text' && <TextAnalyzer onScanComplete={handleScanComplete} />}
        {activeTab === 'history' && (
          <ScanHistory history={history} onClearHistory={handleClearHistory} />
        )}

        <footer className="footer-container">
          <p>© 2026 PhishGuard Capstone Research Project • Multi-Model Anomaly Detection & Threat Intelligence</p>
          <p style={{ marginTop: '0.35rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Powered by FastAPI Backend • XGBoost • Isolation Forest • HuggingFace Transformers
          </p>
        </footer>
      </main>
    </div>
  );
}
