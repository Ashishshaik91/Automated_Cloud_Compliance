import React, { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import Reports from './pages/Reports'
import Policies from './pages/Policies'
import Scans from './pages/Scans'
import Alerts from './pages/Alerts'
import Accounts from './pages/Accounts'
import Login from './pages/Login'

// Simple auth state
const useAuth = () => {
  const [token, setToken] = useState(() => localStorage.getItem('access_token'))
  const login = (t) => { localStorage.setItem('access_token', t); setToken(t) }
  const logout = () => { localStorage.removeItem('access_token'); setToken(null) }
  return { token, login, logout, isAuthenticated: !!token }
}

const Sidebar = ({ logout }) => {
  const navItems = [
    { icon: '🏠', label: 'Dashboard', to: '/dashboard' },
    { icon: '🔍', label: 'Scans', to: '/scans' },
    { icon: '📊', label: 'Reports', to: '/reports' },
    { icon: '📋', label: 'Policies', to: '/policies' },
    { icon: '🔔', label: 'Alerts', to: '/alerts' },
    { icon: '☁️', label: 'Cloud Accounts', to: '/accounts' },
  ]

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-icon">🛡️</div>
        <div>
          <div className="brand-title">ComplianceOps</div>
          <div className="brand-subtitle">Multi-Cloud Security</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section">
          <div className="nav-section-title">Navigation</div>
          {navItems.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            >
              <span className="icon">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </div>

        <div className="nav-section">
          <div className="nav-section-title">Account</div>
          <button className="nav-item" onClick={logout}>
            <span className="icon">🚪</span>
            Sign Out
          </button>
        </div>
      </nav>

      <div style={{ padding: '16px 20px', borderTop: '1px solid var(--color-border)' }}>
        <div style={{ fontSize: '11px', color: 'var(--color-text-dim)' }}>
          Cloud Compliance Platform v1.0
        </div>
        <div style={{ fontSize: '11px', color: 'var(--color-text-dim)' }}>
          PCI-DSS · HIPAA · GDPR · SOC 2
        </div>
      </div>
    </aside>
  )
}

export default function App() {
  const { token, login, logout, isAuthenticated } = useAuth()

  if (!isAuthenticated) {
    return (
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login onLogin={login} />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </BrowserRouter>
    )
  }

  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar logout={logout} />
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/policies" element={<Policies />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/accounts" element={<Accounts />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </div>
    </BrowserRouter>
  )
}
