import React from 'react';
import { Shield, Activity, Globe, MessageSquare, History } from 'lucide-react';
import { API_BASE_URL } from '../config';

export default function Navbar({ activeTab, setActiveTab, apiStatus }) {
  const displayHost = API_BASE_URL.replace(/^https?:\/\//, '');

  return (
    <header className="header-container">
      <a href="#" className="brand-logo">
        <div className="brand-icon">
          <Shield size={22} />
        </div>
        <span>PhishGuard <span style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>WEB PORTAL</span></span>
      </a>

      <div className="tabs-nav">
        <button
          className={`tab-btn ${activeTab === 'url' ? 'active' : ''}`}
          onClick={() => setActiveTab('url')}
        >
          <Globe size={18} />
          URL Inspector
        </button>
        <button
          className={`tab-btn ${activeTab === 'text' ? 'active' : ''}`}
          onClick={() => setActiveTab('text')}
        >
          <MessageSquare size={18} />
          Email / Text Scanner
        </button>
        <button
          className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
          onClick={() => setActiveTab('history')}
        >
          <History size={18} />
          Scan History
        </button>
      </div>

      <div className="badge-status">
        <div className={`pulse-dot ${apiStatus === 'connected' ? '' : 'error'}`}></div>
        <span>{apiStatus === 'connected' ? `API Live (${displayHost})` : 'API Offline'}</span>
      </div>
    </header>
  );
}
