import React, { useState, useEffect, useRef } from 'react'
import { BrowserRouter, Routes, Route, NavLink, Navigate, useLocation } from 'react-router-dom'
import api from './api/client'
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
  Settings,
  GitPullRequest
} from 'lucide-react'
import Dashboard from './pages/Dashboard'
import Reports from './pages/Reports'
import Policies from './pages/Policies'
import Scans from './pages/Scans'
import Alerts from './pages/Alerts'
import Accounts from './pages/Accounts'
import Login from './pages/Login'
import Admin from './pages/Admin'
import Workflows from './pages/Workflows'

// ─── Role helpers ──────────────────────────────────────────────────────────────

const ROLE_RANK = { viewer: 0, dev: 1, auditor: 2, admin: 3 }

const ROLE_BADGES = {
  admin:   { label: 'root',    color: 'var(--color-danger)' },
  auditor: { label: 'auditor', color: 'var(--color-warning)' },
  dev:     { label: 'dev',     color: 'var(--color-info)' },
  viewer:  { label: 'guest',   color: 'var(--color-text-dim)' },
}

// ─── Auth hook ─────────────────────────────────────────────────────────────────

const useAuth = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [role, setRole] = useState('viewer')
  const [loading, setLoading] = useState(true)

  const checkAuth = async () => {
    try {
      const res = await api.get('/auth/me')
      if (res.status === 200) {
        setIsAuthenticated(true)
        setRole(res.data.role || 'viewer')
      } else {
        setIsAuthenticated(false)
        setRole(null)
      }
    } catch {
      setIsAuthenticated(false)
      setRole(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    checkAuth()
  }, [])

  const login = async () => {
    await checkAuth()
  }

  const logout = async () => {
    try {
      await api.post('/auth/logout')
    } catch (e) {
      console.error(e)
    }
    setIsAuthenticated(false)
    setRole(null)
  }

  return { role, login, logout, isAuthenticated, loading }
}

// ─── Role-gated route ──────────────────────────────────────────────────────────

function RoleRoute({ element, minRole, userRole }) {
  if (ROLE_RANK[userRole] >= ROLE_RANK[minRole]) return element
  return <Navigate to="/dashboard" replace />
}

// ─── Page transition wrapper ────────────────────────────────────────────────────

function PageTransition({ children }) {
  const location = useLocation()
  const [displayLocation, setDisplayLocation] = useState(location)
  const [transitionStage, setTransitionStage] = useState('page-enter')

  useEffect(() => {
    if (location.pathname !== displayLocation.pathname) {
      setTransitionStage('page-exit')
    }
  }, [location, displayLocation])

  const handleAnimationEnd = () => {
    if (transitionStage === 'page-exit') {
      setDisplayLocation(location)
      setTransitionStage('page-enter')
    }
  }

  return (
    <div
      className={transitionStage}
      onAnimationEnd={handleAnimationEnd}
      style={{ minHeight: 0 }}
    >
      {children}
    </div>
  )
}

const StatusBar = ({ logout, role, theme, setTheme }) => {
  const badge = ROLE_BADGES[role] || ROLE_BADGES.viewer

  const navItems = [
    { label: '01:Dash', to: '/dashboard',  minRole: 'viewer'  },
    { label: '02:Scan', to: '/scans',      minRole: 'dev'     },
    { label: '03:Repo', to: '/reports',    minRole: 'auditor' },
    { label: '04:Pol',  to: '/policies',   minRole: 'dev'     },
    { label: '05:Alrt', to: '/alerts',     minRole: 'dev'     },
    { label: '06:Cloud',to: '/accounts',   minRole: 'dev'     },
    { label: '07:Wrkflw', to: '/workflows', minRole: 'dev'   },
    { label: '08:Adm',  to: '/admin',      minRole: 'admin'  },
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
  const { role, login, logout, isAuthenticated, loading } = useAuth()
  const [theme, setTheme] = useState(localStorage.getItem('app-theme') || 'cyber-rice')

  useEffect(() => {
    localStorage.setItem('app-theme', theme)
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  if (loading) {
    return <div style={{ height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-primary)', fontFamily: 'var(--font-mono)' }}>INITIALIZING_SECURE_LINK...</div>
  }

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
          <PageTransition>
            <Routes>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/scans"     element={<RoleRoute element={<Scans />}       minRole="dev"     userRole={role} />} />
              <Route path="/reports"   element={<RoleRoute element={<Reports />}     minRole="auditor" userRole={role} />} />
              <Route path="/policies"  element={<RoleRoute element={<Policies role={role} />}    minRole="dev"     userRole={role} />} />
              <Route path="/alerts"    element={<RoleRoute element={<Alerts />}      minRole="dev"     userRole={role} />} />
              <Route path="/accounts"  element={<RoleRoute element={<Accounts />}   minRole="dev"     userRole={role} />} />
              <Route path="/workflows" element={<RoleRoute element={<Workflows />}  minRole="dev"     userRole={role} />} />
              <Route path="/admin"     element={<RoleRoute element={<Admin role={role} />} minRole="admin" userRole={role} />} />
              <Route path="*" element={<Navigate to="/dashboard" replace />} />
            </Routes>
          </PageTransition>
        </main>
      </div>
    </BrowserRouter>
  )
}
