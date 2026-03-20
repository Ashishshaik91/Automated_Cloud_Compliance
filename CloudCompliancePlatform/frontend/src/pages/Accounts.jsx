import React, { useState, useEffect } from 'react'
import api from '../api/client'

export default function Accounts() {
  const [accounts, setAccounts] = useState([])
  const [loading, setLoading] = useState(true)
  const [adding, setAdding] = useState(false)
  
  const [form, setForm] = useState({
    name: '',
    provider: 'aws',
    account_id: '',
    region: 'us-east-1'
  })

  const fetchAccounts = async () => {
    try {
      setLoading(true)
      const res = await api.get('/cloud-accounts')
      setAccounts(res.data)
    } catch (err) {
      console.error('Failed to load accounts', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAccounts()
  }, [])

  const handleAdd = async (e) => {
    e.preventDefault()
    setAdding(true)
    try {
      await api.post('/cloud-accounts', form)
      alert('✅ Cloud account registered successfully!')
      setForm({ name: '', provider: 'aws', account_id: '', region: 'us-east-1' })
      fetchAccounts()
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to add account. Note: This requires Admin privileges.')
    } finally {
      setAdding(false)
    }
  }

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to disable this account?')) return
    try {
      await api.delete(`/cloud-accounts/${id}`)
      fetchAccounts()
    } catch (err) {
      alert('Failed to disable account.')
    }
  }

  return (
    <div className="main-content">
      <header className="top-bar">
        <span style={{ fontWeight: 600, fontSize: 16 }}>Cloud Accounts</span>
        <span style={{ fontSize: 13, color: 'var(--color-text-muted)' }}>Manage connected cloud environments</span>
      </header>

      <div className="page-content fade-in">
        <div className="page-header">
          <h1 className="page-title">Connected Accounts</h1>
          <p className="page-subtitle">Manage your AWS, Azure, and GCP accounts monitored by the compliance platform.</p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 350px) 1fr', gap: 24 }}>
          {/* Add Account Form */}
          <div className="card" style={{ alignSelf: 'start' }}>
            <div className="chart-title">Register Account</div>
            <div className="chart-subtitle">Add a new cloud environment</div>
            
            <form onSubmit={handleAdd}>
              <div className="form-group">
                <label className="form-label">Alias / Name</label>
                <input 
                  type="text" 
                  className="form-input" 
                  placeholder="Production Environment"
                  value={form.name}
                  onChange={e => setForm({...form, name: e.target.value})}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Cloud Provider</label>
                <select 
                  className="form-input"
                  value={form.provider}
                  onChange={e => setForm({...form, provider: e.target.value})}
                  required
                >
                  <option value="aws">AWS</option>
                  <option value="azure">Azure</option>
                  <option value="gcp">Google Cloud</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Provider Account ID</label>
                <input 
                  type="text" 
                  className="form-input" 
                  placeholder={form.provider === 'aws' ? '123456789012' : 'Subscription ID / Project ID'}
                  value={form.account_id}
                  onChange={e => setForm({...form, account_id: e.target.value})}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Primary Region</label>
                <input 
                  type="text" 
                  className="form-input" 
                  placeholder="us-east-1"
                  value={form.region}
                  onChange={e => setForm({...form, region: e.target.value})}
                  required
                />
              </div>

              <button type="submit" className="btn btn-primary btn-full" disabled={adding}>
                {adding ? '+ Registering...' : '+ Register Account'}
              </button>
            </form>
          </div>

          {/* Accounts Table */}
          <div className="card">
            <div className="chart-title">Monitored Environments</div>
            <div className="chart-subtitle">Active accounts connected to the system</div>
            
            {loading ? (
              <div style={{ padding: 40, textAlign: 'center', color: 'var(--color-text-muted)' }}>Loading...</div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Alias Name</th>
                    <th>Provider</th>
                    <th>Account ID</th>
                    <th>Region</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {accounts.length === 0 ? (
                    <tr><td colSpan="6" style={{textAlign:'center', padding: '20px'}}>No accounts registered.</td></tr>
                  ) : accounts.map(acc => (
                    <tr key={acc.id}>
                      <td style={{ fontWeight: 500 }}>{acc.name}</td>
                      <td>
                        <span className="badge medium" style={{ textTransform: 'uppercase' }}>{acc.provider}</span>
                      </td>
                      <td style={{ color: 'var(--color-text-dim)', fontFamily: 'monospace' }}>
                        {acc.account_id}
                      </td>
                      <td style={{ color: 'var(--color-text-muted)', fontSize: 13 }}>{acc.region}</td>
                      <td>
                        <span className={`badge ${acc.is_active ? 'success' : 'danger'}`}>
                          {acc.is_active ? 'Monitoring' : 'Disabled'}
                        </span>
                      </td>
                      <td>
                        <button 
                          className="btn btn-outline" 
                          style={{ padding: '4px 8px', fontSize: 11, borderColor: 'var(--color-danger)', color: 'var(--color-danger)' }}
                          onClick={() => handleDelete(acc.id)}
                        >
                          Disable
                        </button>
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
