import React, { useState } from 'react'
import axios from 'axios'

export default function Login({ onLogin }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const form = new URLSearchParams()
      form.append('username', email)
      form.append('password', password)
      const res = await axios.post('/api/v1/auth/login', form)
      onLogin(res.data.access_token)
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed. Please check your credentials.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      {/* Background orbs */}
      <div className="login-bg-orb" style={{
        width: 600, height: 600, top: -200, left: -200,
        background: 'radial-gradient(circle, rgba(59,130,246,0.3) 0%, transparent 70%)'
      }} />
      <div className="login-bg-orb" style={{
        width: 400, height: 400, bottom: -100, right: -100,
        background: 'radial-gradient(circle, rgba(139,92,246,0.3) 0%, transparent 70%)'
      }} />

      <div className="login-card fade-in">
        <div className="login-logo">🛡️</div>
        <h1 className="login-title">ComplianceOps</h1>
        <p className="login-subtitle">Sign in to your compliance dashboard</p>

        {error && (
          <div style={{
            background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
            borderRadius: 8, padding: '12px 16px', marginBottom: 20,
            color: '#fca5a5', fontSize: 14
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Email Address</label>
            <input
              type="email"
              className="form-input"
              placeholder="admin@example.com"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
              autoComplete="email"
            />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              type="password"
              className="form-input"
              placeholder="••••••••••••"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              autoComplete="current-password"
            />
          </div>
          <button
            type="submit"
            className="btn btn-primary btn-full"
            disabled={loading}
            style={{ marginTop: 8 }}
          >
            {loading ? (
              <><span style={{ width: 16, height: 16, border: '2px solid rgba(255,255,255,0.3)', borderTopColor: 'white', borderRadius: '50%', animation: 'spin 0.8s linear infinite', display: 'inline-block' }} /> Signing in...</>
            ) : (
              <><span>🔐</span> Sign In</>
            )}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: 24, fontSize: 12, color: 'var(--color-text-dim)' }}>
          Protected by JWT + bcrypt authentication
        </p>
      </div>
    </div>
  )
}
