import React, { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom'
import { 
  Menu,
  Shield, 
  LayoutDashboard, 
  Search, 
  FileBox, 
  FileCheck2, 
  Bell, 
  Cloud, 
  Users, 
  LogOut,
  Palette,
  Settings
} from 'lucide-react'
import Dashboard from './pages/Dashboard'
import Reports from './pages/Reports'
import Policies from './pages/Policies'
import Scans from './pages/Scans'
import Alerts from './pages/Alerts'
import Accounts from './pages/Accounts'
import Login from './pages/Login'
import Admin from './pages/Admin'

// ─── Role helpers ──────────────────────────────────────────────────────────────

const ROLE_RANK = { viewer: 0, dev: 1, auditor: 2, admin: 3 }

/** Decode JWT payload (no signature verification — server always validates). */
function decodeJwtPayload(token) {
  try {
    const base64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
    return JSON.parse(atob(base64))
  } catch {
    return {}
  }
}

const ROLE_BADGES = {
  admin:   { label: 'root',    color: 'var(--color-danger)' },
  auditor: { label: 'auditor', color: 'var(--color-warning)' },
  dev:     { label: 'dev',     color: 'var(--color-info)' },
  viewer:  { label: 'guest',   color: 'var(--color-text-dim)' },
}

function getRoleFromToken(token) {
  if (!token) return null
  const payload = decodeJwtPayload(token)
  return payload.role || 'viewer'
}

// ─── Auth hook ─────────────────────────────────────────────────────────────────

const useAuth = () => {
  const [token, setToken] = useState(() => localStorage.getItem('access_token'))
  const [role, setRole] = useState(() => getRoleFromToken(localStorage.getItem('access_token')))

  const login = (t) => {
    localStorage.setItem('access_token', t)
    setToken(t)
    setRole(getRoleFromToken(t))
  }
  const logout = () => {
    localStorage.removeItem('access_token')
    setToken(null)
    setRole(null)
  }

  return { token, role, login, logout, isAuthenticated: !!token }
}

// ─── Role-gated route ──────────────────────────────────────────────────────────

function RoleRoute({ element, minRole, userRole }) {
  if (ROLE_RANK[userRole] >= ROLE_RANK[minRole]) return element
  return <Navigate to="/dashboard" replace />
}

const StatusBar = ({ logout, role, theme, setTheme }) => {
  const badge = ROLE_BADGES[role] || ROLE_BADGES.viewer

  const navItems = [
    { label: '01:Dash', to: '/dashboard', minRole: 'viewer' },
    { label: '02:Scan', to: '/scans',     minRole: 'dev'    },
    { label: '03:Repo', to: '/reports',   minRole: 'auditor' },
    { label: '04:Pol',  to: '/policies',  minRole: 'dev'    },
    { label: '05:Alrt', to: '/alerts',    minRole: 'dev'    },
    { label: '06:Cloud',to: '/accounts',  minRole: 'dev'    },
    { label: '07:Adm',  to: '/admin',     minRole: 'admin'  },
  ]

  const visibleItems = navItems.filter(item => ROLE_RANK[role] >= ROLE_RANK[item.minRole])

  return (
    <div className="status-bar" style={{ 
      background: '#1d1f21', 
      borderBottom: '1px solid rgba(255,255,255,0.05)',
      height: 34,
      padding: '0 12px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      fontFamily: 'var(--font-mono)',
      fontSize: 12
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
        <div style={{ color: 'var(--color-primary)', fontWeight: 900, display: 'flex', alignItems: 'center', gap: 4 }}>
          <Shield size={15} /> DIREWOLF
        </div>
        <div style={{ display: 'flex', gap: 16 }}>
          {visibleItems.map(item => (
            <NavLink 
              key={item.to} 
              to={item.to} 
              className={({ isActive }) =>isActive ? 'active' : ''}
              style={({ isActive }) => ({
                textDecoration: 'none',
                color: isActive ? 'var(--color-primary)' : 'var(--color-text-dim)',
                transition: 'color 0.2s'
              })}
            >
              {item.label}
            </NavLink>
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
        <button 
          onClick={() => setTheme(theme === 'cyber-rice' ? 'direwolf-purple' : 'cyber-rice')}
          style={{ background: 'none', border: 'none', color: 'var(--color-primary)', cursor: 'pointer', display: 'flex', alignItems: 'center', opacity: 0.8 }}
          title="Toggle Theme"
        >
          <Palette size={16} />
        </button>
        <div style={{ color: badge.color, opacity: 0.8 }}>
          [{badge.label.toUpperCase()}]
        </div>
        <button onClick={logout} style={{ background: 'none', border: 'none', color: 'var(--color-danger)', cursor: 'pointer', fontSize: 12, fontFamily: 'inherit', display: 'flex', alignItems: 'center', gap: 4, opacity: 0.7 }}>
          <LogOut size={14} /> EXIT
        </button>
      </div>
    </div>
  )
}

// ─── App ───────────────────────────────────────────────────────────────────────

export default function App() {
  const { token, role, login, logout, isAuthenticated } = useAuth()
  const [theme, setTheme] = useState(localStorage.getItem('app-theme') || 'cyber-rice')

  useEffect(() => {
    localStorage.setItem('app-theme', theme)
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  if (!isAuthenticated) {
    return (
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login setToken={login} />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </BrowserRouter>
    )
  }

  return (
    <BrowserRouter>
      <div className="app-layout" style={{ flexDirection: 'column', padding: 0 }}>
        <StatusBar 
          logout={logout} 
          role={role} 
          theme={theme}
          setTheme={setTheme}
        />
        <main style={{ flex: 1, padding: 24, zoom: 1.25 }}>
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/scans"     element={<RoleRoute element={<Scans />}    minRole="dev"     userRole={role} />} />
            <Route path="/reports"   element={<RoleRoute element={<Reports />}  minRole="auditor" userRole={role} />} />
            <Route path="/policies"  element={<RoleRoute element={<Policies />} minRole="dev"     userRole={role} />} />
            <Route path="/alerts"    element={<RoleRoute element={<Alerts />}   minRole="dev"     userRole={role} />} />
            <Route path="/accounts"  element={<RoleRoute element={<Accounts />} minRole="dev"     userRole={role} />} />
            <Route path="/admin"     element={<RoleRoute element={<Admin role={role} />} minRole="admin" userRole={role} />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
