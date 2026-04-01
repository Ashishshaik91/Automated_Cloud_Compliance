import React, { useState, useEffect } from 'react'
import api from '../api/client'
import TerminalWindow from '../components/TerminalWindow'

export default function Accounts() {
  const [accounts, setAccounts] = useState([])
  const [loading, setLoading] = useState(true)
  const [adding, setAdding] = useState(false)
  const [form, setForm] = useState({ name: '', provider: 'aws', account_id: '', region: 'us-east-1' })

  const fetchAccounts = async () => {
    try {
      setLoading(true)
      const res = await api.get('/cloud-accounts')
      setAccounts(res.data)
    } catch (err) { console.error('Failed to load accounts', err) }
    finally { setLoading(false) }
  }

  useEffect(() => { fetchAccounts() }, [])

  const handleAdd = async (e) => {
    e.preventDefault()
    setAdding(true)
    try {
      await api.post('/cloud-accounts', form)
      setForm({ name: '', provider: 'aws', account_id: '', region: 'us-east-1' })
      fetchAccounts()
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to add account.')
    } finally { setAdding(false) }
  }

  const handleDelete = async (id) => {
    if (!window.confirm('[ WARNING ] THIS WILL DISCONNECT THE UPLINK. PROCEED?')) return
    try {
      await api.delete(`/cloud-accounts/${id}`)
      fetchAccounts()
    } catch (err) { alert('Operation failed.') }
  }

  if (loading && accounts.length === 0) return <div className="loading-center" style={{ fontFamily: 'var(--font-mono)' }}>./loading_cloud_uplinks --verbose</div>

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, fontFamily: 'var(--font-main)' }}>
      <div style={{ borderBottom: '1px solid var(--color-border)', paddingBottom: 16 }}>
        <div style={{ fontSize: 12, color: 'var(--color-primary)', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>$ ls /dev/cloud/uplinks</div>
        <div style={{ fontSize: 20, fontWeight: 900, fontFamily: 'var(--font-mono)' }}>cloud-uplink-manager <span style={{ color: 'var(--color-info)', fontWeight: 400 }}>--multi-provider</span></div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 350px) 1fr', gap: 24 }}>
        <TerminalWindow title="uplink_registration.yaml">
          <form onSubmit={handleAdd} style={{ fontFamily: 'var(--font-mono)' }}>
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', fontSize: 10, color: 'var(--color-text-dim)', marginBottom: 8 }}>{'>>'} ALIAS_NAME</label>
              <input 
                type="text" 
                placeholder="PROD-ENV-01"
                value={form.name}
                onChange={e => setForm({...form, name: e.target.value})}
                style={{
                  width: '100%', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--color-border)',
                  color: 'var(--color-text)', padding: '8px', fontSize: 12, fontFamily: 'var(--font-mono)', outline: 'none'
                }}
                required
              />
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', fontSize: 10, color: 'var(--color-text-dim)', marginBottom: 8 }}>{'>>'} CLOUD_PROVIDER</label>
              <select 
                value={form.provider}
                onChange={e => setForm({...form, provider: e.target.value})}
                style={{
                  width: '100%', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--color-border)',
                  color: 'var(--color-text)', padding: '8px', fontSize: 12, fontFamily: 'var(--font-mono)', outline: 'none'
                }}
                required
              >
                <option value="aws" style={{background: '#1a1b26'}}>AWS [AMAZON]</option>
                <option value="azure" style={{background: '#1a1b26'}}>AZURE [MICROSOFT]</option>
                <option value="gcp" style={{background: '#1a1b26'}}>GCP [GOOGLE]</option>
              </select>
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', fontSize: 10, color: 'var(--color-text-dim)', marginBottom: 8 }}>{'>>'} PROVIDER_UID</label>
              <input 
                type="text" 
                placeholder="UID / SUBSCRIPTION_ID"
                value={form.account_id}
                onChange={e => setForm({...form, account_id: e.target.value})}
                style={{
                  width: '100%', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--color-border)',
                  color: 'var(--color-text)', padding: '8px', fontSize: 12, fontFamily: 'var(--font-mono)', outline: 'none'
                }}
                required
              />
            </div>

            <div style={{ marginBottom: 24 }}>
              <label style={{ display: 'block', fontSize: 10, color: 'var(--color-text-dim)', marginBottom: 8 }}>{'>>'} GEOGRAPHIC_REGION</label>
              <input 
                type="text" 
                placeholder="us-east-1"
                value={form.region}
                onChange={e => setForm({...form, region: e.target.value})}
                style={{
                  width: '100%', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--color-border)',
                  color: 'var(--color-text)', padding: '8px', fontSize: 12, fontFamily: 'var(--font-mono)', outline: 'none'
                }}
                required
              />
            </div>

            <button type="submit" disabled={adding} style={{ 
              width: '100%', background: 'var(--color-primary)', color: '#000', border: 'none', 
              padding: '12px', fontWeight: 900, fontSize: 12, fontFamily: 'var(--font-mono)', cursor: 'pointer'
            }}>
              {adding ? '>> REGISTERING_UPLINK...' : '>> ESTABLISH_CONNECTION'}
            </button>
          </form>
        </TerminalWindow>

        <TerminalWindow title="active_uplinks_inventory.log">
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
              <thead>
                <tr style={{ textAlign: 'left', color: 'var(--color-info)', borderBottom: '1px solid var(--color-border)' }}>
                  <th style={{ padding: '10px 4px' }}>ALIAS</th>
                  <th style={{ padding: '10px 4px' }}>PROVIDER</th>
                  <th style={{ padding: '10px 4px' }}>UID</th>
                  <th style={{ padding: '10px 4px' }}>REGION</th>
                  <th style={{ padding: '10px 4px' }}>STATUS</th>
                  <th style={{ padding: '10px 4px' }}>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {accounts.length === 0 ? (
                  <tr><td colSpan="6" style={{textAlign:'center', padding: '40px', color: 'var(--color-text-dim)'}}>[ NO_UPLINKS_CONNECTED ]</td></tr>
                ) : accounts.map(acc => (
                  <tr key={acc.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    <td style={{ padding: '10px 4px', fontWeight: 700 }}>{acc.name?.toUpperCase()}</td>
                    <td style={{ padding: '10px 4px' }}>
                      <span style={{ color: 'var(--color-accent)', fontWeight: 800 }}>[{acc.provider?.toUpperCase()}]</span>
                    </td>
                    <td style={{ padding: '10px 4px', color: 'var(--color-text-dim)', fontSize: 10 }}>{acc.account_id}</td>
                    <td style={{ padding: '10px 4px' }}>{acc.region?.toUpperCase()}</td>
                    <td style={{ padding: '10px 4px', color: acc.is_active ? 'var(--color-success)' : 'var(--color-danger)' }}>
                      {acc.is_active ? '[ONLINE]' : '[OFFLINE]'}
                    </td>
                    <td style={{ padding: '10px 4px' }}>
                      <button 
                        onClick={() => handleDelete(acc.id)}
                        style={{ background: 'none', border: 'none', color: 'var(--color-danger)', cursor: 'pointer', fontSize: 10, fontWeight: 900 }}
                      >
                        [DISCONNECT]
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </TerminalWindow>
      </div>
    </div>
  )
}
