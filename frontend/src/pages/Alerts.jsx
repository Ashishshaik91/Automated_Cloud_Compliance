import React, { useState, useEffect } from 'react'
import api from '../api/client'
import TerminalWindow from '../components/TerminalWindow'

export default function Alerts() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [saveStatus, setSaveStatus] = useState(null)
  const [integrations, setIntegrations] = useState({
    slack: { enabled: false, webhook: 'https://hooks.slack.com/.../T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX' },
    email: { enabled: true,  address: 'm0rphe3ushaik@gmail.com' }
  })

  const fetchAlerts = async () => {
    try {
      setLoading(true)
      const res = await api.get('/alerts')
      setAlerts(res.data || [])
    } catch (err) {
      console.error('Failed to load alerts', err)
      setAlerts([])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchAlerts() }, [])

  const handleAcknowledge = async (id) => {
    try {
      await api.post(`/alerts/${id}/acknowledge`).catch(() => {})
      setAlerts(alerts.map(a => a.id === id ? { ...a, status: 'acknowledged' } : a))
    } catch (err) { console.error('Failed to acknowledge', err) }
  }

  const toggleIntegration = (type) => {
    setIntegrations(prev => ({ ...prev, [type]: { ...prev[type], enabled: !prev[type].enabled } }))
  }

  const handleSave = async () => {
    setSaveStatus('saving')
    try {
      // Persist to backend so future alert dispatches use the saved address
      await api.post('/alerts/test-email', { email: integrations.email.address })
      setSaveStatus('sent')
    } catch {
      setSaveStatus('error')
    }
    setTimeout(() => setSaveStatus(null), 4000)
  }

  if (loading && alerts.length === 0) return <div className="loading-center" style={{ fontFamily: 'var(--font-mono)' }}>./loading_alerts --tail 20</div>

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, fontFamily: 'var(--font-main)' }}>
      <div style={{ borderBottom: '1px solid var(--color-border)', paddingBottom: 16 }}>
        <div style={{ fontSize: 12, color: 'var(--color-primary)', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>$ tail -f /var/log/compliance/alerts.log</div>
        <div style={{ fontSize: 20, fontWeight: 900, fontFamily: 'var(--font-mono)' }}>security-event-monitor <span style={{ color: 'var(--color-danger)', fontWeight: 400 }}>--high-priority</span></div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '350px 1fr', gap: 24 }}>
        <TerminalWindow title="notif_routing.conf">
          <div style={{ fontFamily: 'var(--font-mono)' }}>
            <div style={{ marginBottom: 24 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <span style={{ fontSize: 11, fontWeight: 800 }}>SLACK_WEBHOOK</span>
                <button 
                  onClick={() => toggleIntegration('slack')}
                  style={{
                    background: 'none',
                    border: `1px solid ${integrations.slack.enabled ? 'var(--color-success)' : 'var(--color-border)'}`,
                    color: integrations.slack.enabled ? 'var(--color-success)' : 'var(--color-text-dim)',
                    padding: '2px 8px',
                    fontSize: 9,
                    fontWeight: 900,
                    cursor: 'pointer'
                  }}
                >
                  [{integrations.slack.enabled ? 'ENABLED' : 'DISABLED'}]
                </button>
              </div>
              <input 
                type="text" 
                value={integrations.slack.webhook}
                onChange={e => setIntegrations({...integrations, slack: {...integrations.slack, webhook: e.target.value}})}
                disabled={!integrations.slack.enabled}
                style={{
                  width: '100%',
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid var(--color-border)',
                  color: 'var(--color-text)',
                  padding: '8px',
                  fontSize: 10,
                  opacity: integrations.slack.enabled ? 1 : 0.3,
                  fontFamily: 'var(--font-mono)'
                }}
              />
            </div>

            <div style={{ marginBottom: 24 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <span style={{ fontSize: 11, fontWeight: 800 }}>SMTP_ALERTS</span>
                <button 
                  onClick={() => toggleIntegration('email')}
                  style={{
                    background: 'none',
                    border: `1px solid ${integrations.email.enabled ? 'var(--color-success)' : 'var(--color-border)'}`,
                    color: integrations.email.enabled ? 'var(--color-success)' : 'var(--color-text-dim)',
                    padding: '2px 8px',
                    fontSize: 9,
                    fontWeight: 900,
                    cursor: 'pointer'
                  }}
                >
                  [{integrations.email.enabled ? 'ENABLED' : 'DISABLED'}]
                </button>
              </div>
              <input 
                type="email" 
                value={integrations.email.address}
                onChange={e => setIntegrations({...integrations, email: {...integrations.email, address: e.target.value}})}
                disabled={!integrations.email.enabled}
                style={{
                  width: '100%',
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid var(--color-border)',
                  color: 'var(--color-text)',
                  padding: '8px',
                  fontSize: 10,
                  opacity: integrations.email.enabled ? 1 : 0.3,
                  fontFamily: 'var(--font-mono)'
                }}
              />
            </div>

            <button
              id="test-btn"
              onClick={handleSave}
              style={{
                width: '100%',
                background: saveStatus === 'sent' ? 'rgba(16,185,129,0.15)' : saveStatus === 'error' ? 'rgba(239,68,68,0.15)' : 'none',
                border: `1px solid ${saveStatus === 'sent' ? 'var(--color-success)' : saveStatus === 'error' ? 'var(--color-danger)' : 'var(--color-primary)'}`,
                color: saveStatus === 'sent' ? 'var(--color-success)' : saveStatus === 'error' ? 'var(--color-danger)' : 'var(--color-primary)',
                padding: '10px',
                fontSize: 11,
                fontWeight: 900,
                cursor: 'pointer',
                fontFamily: 'var(--font-mono)',
                transition: 'all 0.2s ease'
              }}
            >
              {saveStatus === 'saving' ? '>> SENDING_TEST...' : saveStatus === 'sent' ? '>> TEST_EMAIL_SENT ✓' : saveStatus === 'error' ? '>> SMTP_ERROR — CHECK_LOGS' : '>> SAVE & SEND TEST EMAIL'}
            </button>
          </div>
        </TerminalWindow>

        <TerminalWindow title="alert_feed.log">
          {alerts.length === 0 ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)' }}>
              [ OK ] NO_UNRESOLVED_VIOLATIONS_DETECTED
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {alerts.map(alert => (
                <div key={alert.id} style={{ 
                  padding: '12px 16px', 
                  border: '1px solid rgba(255,255,255,0.05)',
                  background: 'rgba(0,0,0,0.1)',
                  borderLeft: `2px solid ${alert.severity === 'critical' ? 'var(--color-danger)' : 'var(--color-warning)'}`,
                  fontFamily: 'var(--font-mono)',
                  opacity: alert.status === 'acknowledged' ? 0.4 : 1
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                    <div style={{ display: 'flex', gap: 8, fontSize: 9 }}>
                      <span style={{ color: alert.severity === 'critical' ? 'var(--color-danger)' : 'var(--color-warning)', fontWeight: 900 }}>[{alert.severity?.toUpperCase()}]</span>
                      <span style={{ color: 'var(--color-primary)', fontWeight: 800 }}>{alert.framework?.toUpperCase()}</span>
                      <span style={{ color: 'var(--color-text-dim)' }}>TIMESTAMP: {new Date(alert.created_at).toISOString().replace('T', ' ').split('.')[0]}</span>
                    </div>
                    {alert.status !== 'acknowledged' && (
                      <button 
                        onClick={() => handleAcknowledge(alert.id)}
                        style={{ background: 'none', border: 'none', color: 'var(--color-success)', cursor: 'pointer', fontSize: 10, fontWeight: 900 }}
                      >
                        [ACK]
                      </button>
                    )}
                  </div>
                  <div style={{ fontSize: 13, fontWeight: 500, color: alert.status === 'acknowledged' ? 'var(--color-text-dim)' : 'var(--color-text)' }}>
                    {'{'} message: "{(alert.message || 'MALFORMED_SIGNAL').toUpperCase()}" {'}'}
                  </div>
                </div>
              ))}
            </div>
          )}
        </TerminalWindow>
      </div>
    </div>
  )
}
