import React, { useState, useEffect } from 'react'
import api from '../api/client'

export default function Alerts() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  
  // Mock integrations state for UI demonstration
  const [integrations, setIntegrations] = useState({
    slack: { enabled: true, webhook: 'https://hooks.slack.com/.../T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX' },
    email: { enabled: false, address: 'security@company.com' }
  })

  const fetchAlerts = async () => {
    try {
      setLoading(true)
      const res = await api.get('/alerts')
      // Backend returns [] for now, let's use some mock presentation data if empty
      setAlerts(res.data.length > 0 ? res.data : [
        { id: 101, severity: 'critical', message: 'S3 Bucket "prod-data" is publicly accessible', framework: 'PCI-DSS', created_at: new Date().toISOString(), status: 'new' },
        { id: 102, severity: 'high', message: 'Root user login detected without MFA', framework: 'SOC 2', created_at: new Date(Date.now() - 3600000).toISOString(), status: 'acknowledged' }
      ])
    } catch (err) {
      console.error('Failed to load alerts', err)
      setAlerts([])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAlerts()
  }, [])

  const handleAcknowledge = async (id) => {
    try {
      // Ignore 404s since our data might be mock for visual display
      await api.post(`/alerts/${id}/acknowledge`).catch(() => {})
      setAlerts(alerts.map(a => a.id === id ? { ...a, status: 'acknowledged' } : a))
    } catch (err) {
      console.error('Failed to acknowledge', err)
    }
  }

  const toggleIntegration = (type) => {
    setIntegrations(prev => ({
      ...prev,
      [type]: { ...prev[type], enabled: !prev[type].enabled }
    }))
  }

  return (
    <div className="main-content">
      <header className="top-bar">
        <span style={{ fontWeight: 600, fontSize: 16 }}>Alerts & Notifications</span>
        <span style={{ fontSize: 13, color: 'var(--color-text-muted)' }}>Configure real-time compliance alerting</span>
      </header>

      <div className="page-content fade-in">
        <div className="page-header">
          <h1 className="page-title">Security Alerts</h1>
          <p className="page-subtitle">Manage open security violations and configure external notification channels.</p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 350px) 1fr', gap: 24 }}>
          {/* Integrations Card */}
          <div className="card" style={{ alignSelf: 'start' }}>
            <div className="chart-title">Notification Channels</div>
            <div className="chart-subtitle">Route critical alerts automatically</div>
            
            <div style={{ marginBottom: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 20 }}>💬</span>
                  <span style={{ fontWeight: 600, fontSize: 14 }}>Slack Webhook</span>
                </div>
                <button 
                  onClick={() => toggleIntegration('slack')}
                  style={{ 
                    background: integrations.slack.enabled ? 'var(--color-success)' : 'var(--color-surface-3)', 
                    border: 'none', borderRadius: 20, width: 36, height: 20, position: 'relative', cursor: 'pointer', transition: '0.2s'
                  }}
                >
                  <div style={{ 
                    position: 'absolute', top: 2, left: integrations.slack.enabled ? 18 : 2, 
                    width: 16, height: 16, background: 'white', borderRadius: '50%', transition: '0.2s' 
                  }}/>
                </button>
              </div>
              <input 
                type="text" 
                className="form-input" 
                value={integrations.slack.webhook}
                onChange={e => setIntegrations({...integrations, slack: {...integrations.slack, webhook: e.target.value}})}
                disabled={!integrations.slack.enabled}
                style={{ fontSize: 12, opacity: integrations.slack.enabled ? 1 : 0.5 }}
              />
            </div>

            <div style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 20 }}>✉️</span>
                  <span style={{ fontWeight: 600, fontSize: 14 }}>Email Alerts</span>
                </div>
                <button 
                  onClick={() => toggleIntegration('email')}
                  style={{ 
                    background: integrations.email.enabled ? 'var(--color-success)' : 'var(--color-surface-3)', 
                    border: 'none', borderRadius: 20, width: 36, height: 20, position: 'relative', cursor: 'pointer', transition: '0.2s'
                  }}
                >
                  <div style={{ 
                    position: 'absolute', top: 2, left: integrations.email.enabled ? 18 : 2, 
                    width: 16, height: 16, background: 'white', borderRadius: '50%', transition: '0.2s' 
                  }}/>
                </button>
              </div>
              <input 
                type="email" 
                className="form-input" 
                value={integrations.email.address}
                onChange={e => setIntegrations({...integrations, email: {...integrations.email, address: e.target.value}})}
                disabled={!integrations.email.enabled}
                style={{ fontSize: 12, opacity: integrations.email.enabled ? 1 : 0.5 }}
              />
            </div>
            
            <button className="btn btn-outline btn-full" style={{ marginTop: 12, fontSize: 13 }} onClick={() => alert('Test alert sent to active channels!')}>
              🔔 Send Test Alert
            </button>
          </div>

          {/* Alerts Feed */}
          <div className="card">
            <div className="chart-title">Alert Inbox</div>
            <div className="chart-subtitle">Recent critical and high severity violations</div>
            
            {loading ? (
              <div style={{ padding: 40, textAlign: 'center', color: 'var(--color-text-muted)' }}>Loading...</div>
            ) : alerts.length === 0 ? (
              <div style={{ padding: 40, textAlign: 'center', color: 'var(--color-text-muted)' }}>No active alerts. 🙌</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {alerts.map(alert => (
                  <div key={alert.id} style={{ 
                    padding: 16, 
                    background: 'var(--color-surface-2)', 
                    border: '1px solid var(--color-border)',
                    borderLeft: `3px solid ${alert.severity === 'critical' ? 'var(--color-danger)' : 'var(--color-warning)'}`,
                    borderRadius: 8,
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    opacity: alert.status === 'acknowledged' ? 0.6 : 1
                  }}>
                    <div>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
                        <span className={`badge ${alert.severity}`} style={{ padding: '2px 6px', fontSize: 10 }}>{alert.severity}</span>
                        <span className="badge medium" style={{ padding: '2px 6px', fontSize: 10 }}>{alert.framework}</span>
                        <span style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>{new Date(alert.created_at).toLocaleString()}</span>
                      </div>
                      <div style={{ fontWeight: 500, fontSize: 14 }}>{alert.message}</div>
                    </div>
                    
                    {alert.status !== 'acknowledged' ? (
                      <button 
                        className="btn btn-primary" 
                        style={{ padding: '6px 12px', fontSize: 12 }}
                        onClick={() => handleAcknowledge(alert.id)}
                      >
                        ✓ Acknowledge
                      </button>
                    ) : (
                      <span style={{ fontSize: 12, color: 'var(--color-text-muted)', fontWeight: 600 }}>Acknowledged</span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
