import React, { useState, useEffect } from 'react'
import api from '../api/client'

export default function Scans() {
  const [scans, setScans] = useState([])
  const [accounts, setAccounts] = useState([])
  const [loading, setLoading] = useState(true)
  const [triggering, setTriggering] = useState(false)
  
  const [form, setForm] = useState({ account_id: '', framework: 'all' })

  const fetchData = async () => {
    try {
      setLoading(true)
      const [scansRes, accRes] = await Promise.all([
        api.get('/scans'),
        api.get('/cloud-accounts')
      ])
      setScans(scansRes.data)
      setAccounts(accRes.data)
      if (accRes.data.length > 0 && !form.account_id) {
        setForm(f => ({ ...f, account_id: accRes.data[0].id }))
      }
    } catch (err) {
      console.error('Failed to load scans data', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const handleTrigger = async (e) => {
    e.preventDefault()
    if (!form.account_id) return alert('Please select an account')
    
    setTriggering(true)
    try {
      await api.post('/scans/trigger', {
        account_id: parseInt(form.account_id),
        framework: form.framework
      })
      alert('✅ Scan triggered successfully!')
      fetchData()
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to trigger scan')
    } finally {
      setTriggering(false)
    }
  }

  return (
    <div className="main-content">
      <header className="top-bar">
        <span style={{ fontWeight: 600, fontSize: 16 }}>Scan Manager</span>
        <span style={{ fontSize: 13, color: 'var(--color-text-muted)' }}>Trigger and review security scans</span>
      </header>

      <div className="page-content fade-in">
        <div className="page-header">
          <h1 className="page-title">Compliance Scans</h1>
          <p className="page-subtitle">View scan history and manually trigger evaluations.</p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 350px) 1fr', gap: 24 }}>
          {/* Trigger Scan Card */}
          <div className="card" style={{ alignSelf: 'start' }}>
            <div className="chart-title">Trigger New Scan</div>
            <div className="chart-subtitle">Run an immediate evaluation</div>
            
            <form onSubmit={handleTrigger}>
              <div className="form-group">
                <label className="form-label">Target Cloud Account</label>
                <select 
                  className="form-input" 
                  value={form.account_id}
                  onChange={e => setForm({...form, account_id: e.target.value})}
                  required
                >
                  <option value="" disabled>Select account...</option>
                  {accounts.map(acc => (
                    <option key={acc.id} value={acc.id}>{acc.name} ({acc.provider.toUpperCase()})</option>
                  ))}
                </select>
              </div>
              
              <div className="form-group">
                <label className="form-label">Compliance Framework</label>
                <select 
                  className="form-input"
                  value={form.framework}
                  onChange={e => setForm({...form, framework: e.target.value})}
                >
                  <option value="all">All Activated Frameworks</option>
                  <option value="pci_dss">PCI-DSS</option>
                  <option value="hipaa">HIPAA</option>
                  <option value="gdpr">GDPR</option>
                  <option value="soc2">SOC 2</option>
                </select>
              </div>

              <button type="submit" className="btn btn-primary btn-full" disabled={triggering}>
                {triggering ? '⚡ Triggering...' : '⚡ Start Scan'}
              </button>
            </form>
          </div>

          {/* Scan History Table */}
          <div className="card">
            <div className="chart-title">Scan History</div>
            <div className="chart-subtitle">Recent compliance evaluations</div>
            
            {loading ? (
              <div style={{ padding: 40, textAlign: 'center', color: 'var(--color-text-muted)' }}>Loading...</div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Date</th>
                    <th>Account</th>
                    <th>Framework</th>
                    <th>Score</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.length === 0 ? (
                    <tr><td colSpan="6" style={{textAlign:'center', padding: '20px'}}>No scans found</td></tr>
                  ) : scans.map(scan => (
                    <tr key={scan.id}>
                      <td style={{ color: 'var(--color-text-dim)' }}>#{scan.id}</td>
                      <td>{new Date(scan.started_at).toLocaleString()}</td>
                      <td>{accounts.find(a => a.id === scan.account_id)?.name || `Account ${scan.account_id}`}</td>
                      <td><span className="badge medium" style={{textTransform:'uppercase'}}>{scan.framework}</span></td>
                      <td style={{ fontWeight: 700, color: scan.compliance_score >= 80 ? 'var(--color-success)' : 'var(--color-danger)'}}>
                        {scan.compliance_score.toFixed(1)}%
                      </td>
                      <td>
                        <span className={`badge ${scan.status === 'completed' ? 'success' : 'warning'}`}>
                          {scan.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
