import React, { useState, useEffect } from 'react'
import api from '../api/client'
import { Zap } from 'lucide-react'
import TerminalWindow from '../components/TerminalWindow'

export default function Scans() {
// ... existing state and fetchData logic ...
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
      fetchData()
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to trigger scan')
    } finally {
      setTriggering(false)
    }
  }

  if (loading && scans.length === 0) return <div className="loading-center" style={{ fontFamily: 'var(--font-mono)' }}>./loading_scan_engine --status ready</div>

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div style={{ borderBottom: '1px solid var(--color-border)', paddingBottom: 16 }}>
        <div style={{ fontSize: 12, color: 'var(--color-primary)', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>$ ./compliance_engine --ops scans</div>
        <div style={{ fontSize: 20, fontWeight: 900, fontFamily: 'var(--font-mono)' }}>scan-operations-center <span style={{ color: 'var(--color-info)', fontWeight: 400 }}>--live</span></div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '350px 1fr', gap: 24 }}>
        <TerminalWindow title="trigger_config.yaml">
          <form onSubmit={handleTrigger} style={{ fontFamily: 'var(--font-mono)' }}>
            <div style={{ marginBottom: 20 }}>
              <label style={{ display: 'block', fontSize: 10, color: 'var(--color-text-dim)', marginBottom: 8 }}>{'>>'} TARGET_ACCOUNT</label>
              <select 
                value={form.account_id}
                onChange={e => setForm({...form, account_id: e.target.value})}
                style={{
                  width: '100%',
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid var(--color-border)',
                  color: 'var(--color-text)',
                  padding: '8px',
                  fontSize: 12,
                  fontFamily: 'var(--font-mono)',
                  outline: 'none'
                }}
                required
              >
                <option value="" disabled>SELECT_ACCOUNT...</option>
                {accounts.map(acc => (
                  <option key={acc.id} value={acc.id} style={{background: '#1a1b26'}}>{acc.name} [{acc.provider?.toUpperCase() || 'UNKNOWN'}]</option>
                ))}
              </select>
            </div>
            
            <div style={{ marginBottom: 24 }}>
              <label style={{ display: 'block', fontSize: 10, color: 'var(--color-text-dim)', marginBottom: 8 }}>{'>>'} FRAMEWORK_SCOPE</label>
              <select 
                value={form.framework}
                onChange={e => setForm({...form, framework: e.target.value})}
                style={{
                  width: '100%',
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid var(--color-border)',
                  color: 'var(--color-text)',
                  padding: '8px',
                  fontSize: 12,
                  fontFamily: 'var(--font-mono)',
                  outline: 'none'
                }}
              >
                <option value="all" style={{background: '#1a1b26'}}>ALL_FRAMEWORKS</option>
                <option value="pci_dss" style={{background: '#1a1b26'}}>PCI-DSS</option>
                <option value="hipaa" style={{background: '#1a1b26'}}>HIPAA</option>
                <option value="gdpr" style={{background: '#1a1b26'}}>GDPR</option>
                <option value="soc2" style={{background: '#1a1b26'}}>SOC 2</option>
                <option value="nist" style={{background: '#1a1b26'}}>NIST</option>
                <option value="cis" style={{background: '#1a1b26'}}>CIS</option>
                <option value="owasp" style={{background: '#1a1b26'}}>OWASP</option>
                <option value="custom" style={{background: '#1a1b26'}}>CUSTOM</option>
              </select>
            </div>

            <button 
              type="submit" 
              disabled={triggering} 
              style={{ 
                width: '100%', 
                background: 'var(--color-primary)', 
                color: '#000', 
                border: 'none', 
                padding: '12px', 
                fontWeight: 900, 
                fontSize: 12, 
                fontFamily: 'var(--font-mono)',
                cursor: 'pointer',
                borderRadius: 2
              }}
            >
              {triggering ? '>> INITIATING_SCAN...' : '>> EXECUTE_COMPLIANCE_SCAN'}
            </button>
          </form>
        </TerminalWindow>

        <TerminalWindow title="scan_history_buffer.log">
          <div style={{ overflowX: 'auto', maxHeight: '500px' }}>
            <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
              <thead>
                <tr style={{ textAlign: 'left', color: 'var(--color-info)', borderBottom: '1px solid var(--color-border)' }}>
                  <th style={{ padding: '10px 4px' }}>SCAN_ID</th>
                  <th style={{ padding: '10px 4px' }}>TIMESTAMP</th>
                  <th style={{ padding: '10px 4px' }}>ACCOUNT</th>
                  <th style={{ padding: '10px 4px' }}>FRAMEWORK</th>
                  <th style={{ padding: '10px 4px' }}>SCORE</th>
                  <th style={{ padding: '10px 4px' }}>STATUS</th>
                </tr>
              </thead>
              <tbody>
                {scans.length === 0 ? (
                  <tr><td colSpan="6" style={{textAlign:'center', padding: '40px', color: 'var(--color-text-dim)'}}>[ NO_RECORDS_FOUND ]</td></tr>
                ) : scans.map(scan => (
                  <tr key={scan.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    <td style={{ padding: '10px 4px', color: 'var(--color-text-dim)' }}>0x{(scan.id || 0).toString(16).padStart(4, '0')}</td>
                    <td style={{ padding: '10px 4px' }}>{scan.started_at ? new Date(scan.started_at).toISOString().split('T')[0] : 'N/A'}</td>
                    <td style={{ padding: '10px 4px', color: 'var(--color-accent)' }}>{accounts.find(a => a.id === scan.account_id)?.name || `ACC_${scan.account_id}`}</td>
                    <td style={{ padding: '10px 4px' }}>{scan.framework?.toUpperCase() || 'ALL'}</td>
                    <td style={{ padding: '10px 4px', fontWeight: 900, color: (scan.compliance_score || 0) >= 80 ? 'var(--color-success)' : 'var(--color-danger)'}}>
                      {(scan.compliance_score || 0).toFixed(1)}%
                    </td>
                    <td style={{ padding: '10px 4px', color: scan.status === 'completed' ? 'var(--color-success)' : 'var(--color-warning)' }}>
                      [{scan.status?.toUpperCase() || 'PENDING'}]
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
