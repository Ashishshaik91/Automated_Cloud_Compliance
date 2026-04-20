import React, { useState, useEffect } from 'react'
import api from '../api/client'
import { ShieldAlert, ShieldCheck, KeyRound, Copy } from 'lucide-react'

export default function Settings() {
  const [mfaEnabled, setMfaEnabled] = useState(false)
  const [loading, setLoading] = useState(true)
  
  // Enrolment state
  const [enrolData, setEnrolData] = useState(null)
  const [confirmCode, setConfirmCode] = useState('')
  const [enrolError, setEnrolError] = useState('')
  
  // Disable state
  const [disableCode, setDisableCode] = useState('')
  const [disableError, setDisableError] = useState('')
  const [useBackup, setUseBackup] = useState(false)

  // Fetch initial state
  const fetchStatus = async () => {
    try {
      const res = await api.get('/auth/me')
      setMfaEnabled(res.data.mfa_enabled || false)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchStatus()
  }, [])

  // Start Enrolment
  const handleEnrolInit = async () => {
    try {
      setEnrolError('')
      const res = await api.post('/auth/mfa/enrol')
      setEnrolData(res.data)
    } catch (e) {
      setEnrolError(e.response?.data?.detail || 'Failed to initialize MFA enrolment')
    }
  }

  // Confirm Enrolment
  const handleConfirm = async (e) => {
    e.preventDefault()
    try {
      setEnrolError('')
      await api.post('/auth/mfa/confirm', { code: confirmCode })
      // Success
      setMfaEnabled(true)
      // We keep enrolData around just to show the backup codes one last time
    } catch (e) {
      setEnrolError(e.response?.data?.detail || 'Invalid code. Check your authenticator app.')
    }
  }

  // Disable MFA
  const handleDisable = async (e) => {
    e.preventDefault()
    try {
      setDisableError('')
      await api.post('/auth/mfa/disable', { code: disableCode, use_backup: useBackup })
      setMfaEnabled(false)
      setDisableCode('')
      setEnrolData(null)
      setConfirmCode('')
    } catch (e) {
      setDisableError(e.response?.data?.detail || 'Failed to disable MFA. Invalid code.')
    }
  }

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text)
  }

  if (loading) return <div style={{ color: 'var(--color-primary)', fontFamily: 'var(--font-mono)' }}>Loading Security Settings...</div>

  return (
    <div style={{ maxWidth: 800, margin: '0 auto', fontFamily: 'var(--font-mono)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 32 }}>
        <KeyRound size={28} color="var(--color-primary)" />
        <h1 style={{ margin: 0, fontSize: 24, color: 'var(--color-text)' }}>Security Settings</h1>
      </div>

      <div className="card" style={{ padding: 32, border: '1px solid var(--color-border)', background: 'rgba(255,255,255,0.02)' }}>
        
        {/* === STATUS: ENABLED === */}
        {mfaEnabled && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24, color: 'var(--color-success)' }}>
              <ShieldCheck size={24} />
              <h2 style={{ margin: 0, fontSize: 18 }}>Multi-Factor Authentication is ENABLED</h2>
            </div>
            
            {/* If we just enrolled, show backup codes */}
            {enrolData && (
              <div style={{ background: 'rgba(255,100,100,0.1)', border: '1px solid var(--color-danger)', padding: 20, marginBottom: 32, borderRadius: 4 }}>
                <h3 style={{ color: 'var(--color-danger)', marginTop: 0 }}>Save Your Backup Codes</h3>
                <p style={{ fontSize: 13, color: 'var(--color-text-dim)' }}>
                  This is the ONLY time these codes will be shown. Save them in a secure place (like a password manager). 
                  If you lose your device, these codes are the only way to recover your account.
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginTop: 16 }}>
                  {enrolData.backup_codes.map((code, idx) => (
                    <div key={idx} style={{ background: '#000', padding: '8px 12px', border: '1px solid var(--color-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <code style={{ fontSize: 14, letterSpacing: 2 }}>{code}</code>
                      <button onClick={() => copyToClipboard(code)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-primary)' }}>
                        <Copy size={14} />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div style={{ borderTop: '1px solid var(--color-border)', paddingTop: 24 }}>
              <h3 style={{ fontSize: 15, color: 'var(--color-text)', marginBottom: 16 }}>Disable MFA</h3>
              <form onSubmit={handleDisable} style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 400 }}>
                <div>
                  <label style={{ display: 'block', fontSize: 11, color: 'var(--color-text-dim)', marginBottom: 8 }}>
                    AUTHORIZATION_CODE
                  </label>
                  <input
                    type="text"
                    value={disableCode}
                    onChange={e => setDisableCode(e.target.value)}
                    placeholder={useBackup ? "8-character backup code" : "6-digit TOTP code"}
                    style={{
                      width: '100%',
                      background: 'rgba(255,255,255,0.03)',
                      border: '1px solid var(--color-border)',
                      padding: '12px',
                      color: 'var(--color-text)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 14,
                      outline: 'none'
                    }}
                    required
                  />
                </div>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--color-text-dim)', cursor: 'pointer' }}>
                  <input 
                    type="checkbox" 
                    checked={useBackup} 
                    onChange={e => setUseBackup(e.target.checked)}
                  />
                  Use a backup code instead of TOTP
                </label>
                {disableError && <div style={{ color: 'var(--color-danger)', fontSize: 12 }}>{disableError}</div>}
                <button type="submit" className="btn btn-danger" style={{ width: 'fit-content' }}>
                  Disable MFA
                </button>
              </form>
            </div>
          </div>
        )}

        {/* === STATUS: DISABLED === */}
        {!mfaEnabled && !enrolData && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24, color: 'var(--color-warning)' }}>
              <ShieldAlert size={24} />
              <h2 style={{ margin: 0, fontSize: 18 }}>Multi-Factor Authentication is DISABLED</h2>
            </div>
            <p style={{ color: 'var(--color-text-dim)', fontSize: 14, lineHeight: 1.6, marginBottom: 24 }}>
              Protect your account from unauthorized access by requiring a second authentication method in addition to your password. 
              You will need an authenticator app like Google Authenticator or Authy.
            </p>
            {enrolError && <div style={{ color: 'var(--color-danger)', fontSize: 12, marginBottom: 16 }}>{enrolError}</div>}
            <button onClick={handleEnrolInit} className="btn btn-primary">
              Setup Authenticator App
            </button>
          </div>
        )}

        {/* === STATUS: ENROLLING === */}
        {!mfaEnabled && enrolData && (
          <div>
            <h2 style={{ margin: 0, fontSize: 18, color: 'var(--color-text)', marginBottom: 24 }}>Configure Authenticator App</h2>
            
            <div style={{ display: 'flex', gap: 40, flexWrap: 'wrap' }}>
              <div>
                <p style={{ fontSize: 13, color: 'var(--color-text-dim)', marginBottom: 16 }}>
                  1. Scan this QR code with your authenticator app:
                </p>
                <div style={{ background: '#fff', padding: 16, display: 'inline-block', borderRadius: 8, marginBottom: 16 }}>
                  <img src={`data:image/png;base64,${enrolData.qr_png_b64}`} alt="MFA QR Code" width={200} height={200} />
                </div>
                <p style={{ fontSize: 12, color: 'var(--color-text-dim)', margin: 0 }}>
                  Or enter this code manually:<br/>
                  <code style={{ color: 'var(--color-primary)', fontSize: 14, display: 'inline-block', marginTop: 8 }}>{enrolData.manual_secret}</code>
                </p>
              </div>

              <div style={{ flex: 1, minWidth: 250 }}>
                <p style={{ fontSize: 13, color: 'var(--color-text-dim)', marginBottom: 16 }}>
                  2. Enter the 6-digit code generated by the app:
                </p>
                <form onSubmit={handleConfirm} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <input
                    type="text"
                    maxLength={6}
                    placeholder="123456"
                    value={confirmCode}
                    onChange={e => setConfirmCode(e.target.value.replace(/\D/g, ''))}
                    style={{
                      width: '100%',
                      background: 'rgba(255,255,255,0.03)',
                      border: '1px solid var(--color-border)',
                      padding: '12px',
                      color: 'var(--color-text)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 18,
                      letterSpacing: 4,
                      outline: 'none',
                      textAlign: 'center'
                    }}
                    required
                  />
                  {enrolError && <div style={{ color: 'var(--color-danger)', fontSize: 12 }}>{enrolError}</div>}
                  <button type="submit" className="btn btn-primary">
                    Verify and Activate
                  </button>
                  <button type="button" onClick={() => setEnrolData(null)} style={{ background: 'none', border: 'none', color: 'var(--color-text-dim)', cursor: 'pointer', fontSize: 12, marginTop: 8 }}>
                    Cancel
                  </button>
                </form>
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  )
}
