import React from 'react';
import { Shield, Globe, MessageSquare, History } from 'lucide-react';
import { API_BASE_URL } from '../config';

export default function Navbar({ activeTab, setActiveTab, apiStatus }) {
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
          className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
          onClick={() => setActiveTab('history')}
        >
          <History size={18} />
          Scan History
        </button>
      </div>

      <div className="badge-status">
        <div className="pulse-dot"></div>
        <span>API Online</span>
      </div>
    </header>
  );
}
