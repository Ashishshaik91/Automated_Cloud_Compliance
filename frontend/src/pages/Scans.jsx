import React, { useState, useEffect, useRef } from 'react'
import api from '../api/client'
import TerminalWindow from '../components/TerminalWindow'

const C = {
  purple: '#8b5cf6', cyan: '#22d3ee', green: '#4ade80',
  orange: '#fb923c', red: '#f87171', dim: 'rgba(255,255,255,0.35)',
  text: '#e2e8f0', bg: '#0d0a1c',
}
const mono = { fontFamily: 'var(--font-mono)' }

const FRAMEWORKS = [
  { value: 'all',     label: 'ALL_FRAMEWORKS' },
  { value: 'cis',     label: 'CIS' },
  { value: 'pci_dss', label: 'PCI-DSS' },
  { value: 'hipaa',   label: 'HIPAA' },
  { value: 'gdpr',    label: 'GDPR' },
  { value: 'soc2',    label: 'SOC 2' },
  { value: 'nist',    label: 'NIST' },
  { value: 'owasp',   label: 'OWASP' },
  { value: 'custom',  label: 'CUSTOM' },
]

// Derive scan status from DB fields since ScanResult has no status column
const scanStatus = (scan) => {
  if (scan.completed_at) return 'completed'
  if (scan.total_checks > 0) return 'completed'   // fallback: has checks = done
  return 'running'
}

export default function Scans() {
  const [scans,      setScans]      = useState([])
  const [accounts,   setAccounts]   = useState([])
  const [loading,    setLoading]    = useState(true)
  const [triggering, setTriggering] = useState(false)
  const [refreshing, setRefreshing] = useState(false)

  // Single-account form (legacy)
  const [form, setForm] = useState({ account_id: '', framework: 'all' })

  // Multi-account/framework mode
  const [mode,      setMode]      = useState('single')  // 'single' | 'multi'
  const [selAccts,  setSelAccts]  = useState(new Set())
  const [selFw,     setSelFw]     = useState('all')

  const pollRef  = useRef(null)
  const maxIdRef = useRef(0)

  const fetchData = async (silent = false) => {
    try {
      if (!silent) setLoading(true)
      const [scansRes, accRes] = await Promise.all([
        api.get('/scans?limit=100'),
        api.get('/cloud-accounts')
      ])
      setScans(scansRes.data)
      setAccounts(accRes.data)
      if (accRes.data.length > 0 && !form.account_id) {
        setForm(f => ({ ...f, account_id: accRes.data[0].id }))
      }
      // Pre-select all accounts in multi mode
      if (accRes.data.length > 0 && selAccts.size === 0) {
        setSelAccts(new Set(accRes.data.map(a => a.id)))
      }
      return scansRes.data
    } catch (err) {
      console.error('Failed to load scans data', err)
      return null
    } finally {
      if (!silent) setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
    return () => clearInterval(pollRef.current)
  }, [])

  const startPolling = (prevMaxId) => {
    clearInterval(pollRef.current)
    let attempts = 0
    pollRef.current = setInterval(async () => {
      attempts++
      const data = await fetchData(true)
      if (!data) return
      const newCompleted = data.find(
        s => s.id > prevMaxId && scanStatus(s) === 'completed'
      )
      if (newCompleted || attempts >= 20) {
        clearInterval(pollRef.current)
        setRefreshing(false)
      }
    }, 3000)
  }

  // Single-account trigger (original form)
  const handleTrigger = async (e) => {
    e.preventDefault()
    if (!form.account_id) return alert('Please select an account')
    const prevMaxId = scans.reduce((max, s) => Math.max(max, s.id || 0), 0)
    maxIdRef.current = prevMaxId
    setTriggering(true)
    setRefreshing(true)
    try {
      await api.post('/scans/trigger', {
        account_id: parseInt(form.account_id),
        framework: form.framework
      })
      await fetchData(true)
      startPolling(prevMaxId)
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to trigger scan')
      setRefreshing(false)
    } finally {
      setTriggering(false)
    }
  }

  // Multi-account trigger
  const handleMultiTrigger = async () => {
    const ids = [...selAccts]
    if (ids.length === 0) return alert('Select at least one account')
    const prevMaxId = scans.reduce((max, s) => Math.max(max, s.id || 0), 0)
    maxIdRef.current = prevMaxId
    setTriggering(true)
    setRefreshing(true)
    try {
      await Promise.allSettled(
        ids.map(id => api.post('/scans/trigger', { account_id: id, framework: selFw }))
      )
      await fetchData(true)
      startPolling(prevMaxId)
    } catch (err) {
      console.error('Multi-scan error', err)
      setRefreshing(false)
    } finally {
      setTriggering(false)
    }
  }

  if (loading && scans.length === 0) return (
    <div className="loading-center" style={mono}>
      ./loading_scan_engine --status ready
    </div>
  )

  const acctColor = (provider) =>
    provider === 'gcp' ? C.cyan : provider === 'aws' ? C.orange : C.purple

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* Top progress bar */}
      {refreshing && <div className="refresh-bar" key={Date.now()} />}

      <div style={{ borderBottom: '1px solid var(--color-border)', paddingBottom: 16 }}>
        <div style={{ fontSize: 12, color: 'var(--color-primary)', fontWeight: 800, ...mono }}>
          $ ./compliance_engine --ops scans
        </div>
        <div style={{ fontSize: 20, fontWeight: 900, ...mono }}>
          scan-operations-center <span style={{ color: 'var(--color-info)', fontWeight: 400 }}>--live</span>
          {refreshing && (
            <span style={{ fontSize: 11, color: 'var(--color-warning)', marginLeft: 16, fontWeight: 400 }}>
              scanning in progress...
            </span>
          )}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '380px 1fr', gap: 24, alignItems: 'start' }}>

        {/* ── Trigger Panel ── */}
        <TerminalWindow title="trigger_config.yaml">
          <div style={mono}>

            {/* Mode toggle */}
            <div style={{ display: 'flex', gap: 0, marginBottom: 20, border: `1px solid ${C.purple}44`, borderRadius: 3, overflow: 'hidden' }}>
              {[['single', 'SINGLE ACCOUNT'], ['multi', 'MULTI ACCOUNT']].map(([m, label]) => (
                <button
                  key={m}
                  onClick={() => setMode(m)}
                  style={{
                    flex: 1, padding: '6px 0', fontSize: 9, ...mono, fontWeight: 800,
                    background: mode === m ? `${C.purple}22` : 'none',
                    border: 'none',
                    borderRight: m === 'single' ? `1px solid ${C.purple}44` : 'none',
                    color: mode === m ? C.purple : C.dim,
                    cursor: 'pointer', transition: 'all 0.15s',
                  }}
                >
                  {label}
                </button>
              ))}
            </div>

            {mode === 'single' ? (
              /* ── Single account form ── */
              <form onSubmit={handleTrigger}>
                <div style={{ marginBottom: 20 }}>
                  <label style={{ display: 'block', fontSize: 10, color: C.dim, marginBottom: 8 }}>
                    {'>> TARGET_ACCOUNT'}
                  </label>
                  <select
                    value={form.account_id}
                    onChange={e => setForm({ ...form, account_id: e.target.value })}
                    style={{
                      width: '100%', background: 'rgba(255,255,255,0.05)',
                      border: '1px solid var(--color-border)', color: 'var(--color-text)',
                      padding: '8px', fontSize: 12, ...mono, outline: 'none'
                    }}
                    required
                  >
                    <option value="" disabled>SELECT_ACCOUNT...</option>
                    {accounts.map(acc => (
                      <option key={acc.id} value={acc.id} style={{ background: '#1a1b26' }}>
                        {acc.name} [{acc.provider?.toUpperCase() || 'UNKNOWN'}]
                      </option>
                    ))}
                  </select>
                </div>

                <div style={{ marginBottom: 24 }}>
                  <label style={{ display: 'block', fontSize: 10, color: C.dim, marginBottom: 8 }}>
                    {'>> FRAMEWORK_SCOPE'}
                  </label>
                  <select
                    value={form.framework}
                    onChange={e => setForm({ ...form, framework: e.target.value })}
                    style={{
                      width: '100%', background: 'rgba(255,255,255,0.05)',
                      border: '1px solid var(--color-border)', color: 'var(--color-text)',
                      padding: '8px', fontSize: 12, ...mono, outline: 'none'
                    }}
                  >
                    {FRAMEWORKS.map(f => (
                      <option key={f.value} value={f.value} style={{ background: '#1a1b26' }}>{f.label}</option>
                    ))}
                  </select>
                </div>

                <button
                  type="submit"
                  disabled={triggering || refreshing}
                  style={{
                    width: '100%',
                    background: triggering || refreshing ? 'var(--color-surface-3)' : 'var(--color-primary)',
                    color: triggering || refreshing ? 'var(--color-text-dim)' : '#000',
                    border: 'none', padding: '12px', fontWeight: 900, fontSize: 12, ...mono,
                    cursor: triggering || refreshing ? 'not-allowed' : 'pointer',
                    borderRadius: 2, transition: 'all 0.2s ease'
                  }}
                >
                  {triggering ? '>> INITIATING_SCAN...' : refreshing ? '>> SCAN_IN_PROGRESS...' : '>> EXECUTE_COMPLIANCE_SCAN'}
                </button>
              </form>
            ) : (
              /* ── Multi account/framework panel ── */
              <div>
                <div style={{ display: 'flex', gap: 20, marginBottom: 20 }}>

                  {/* Accounts */}
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 10, color: C.dim, marginBottom: 10 }}>{'>> TARGET_ACCOUNTS'}</div>
                    {accounts.map(acc => {
                      const col = acctColor(acc.provider)
                      const checked = selAccts.has(acc.id)
                      return (
                        <label
                          key={acc.id}
                          style={{
                            display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer',
                            marginBottom: 8, padding: '6px 8px',
                            background: checked ? `${col}18` : 'rgba(255,255,255,0.02)',
                            border: `1px solid ${checked ? col + '55' : 'rgba(255,255,255,0.08)'}`,
                            borderRadius: 3, transition: 'all 0.15s',
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={e => {
                              const s = new Set(selAccts)
                              e.target.checked ? s.add(acc.id) : s.delete(acc.id)
                              setSelAccts(s)
                            }}
                            style={{ accentColor: col, width: 13, height: 13 }}
                          />
                          <div>
                            <div style={{ fontSize: 10, color: checked ? col : C.dim, fontWeight: 800 }}>{acc.name}</div>
                            <div style={{ fontSize: 8, color: C.dim }}>{acc.provider?.toUpperCase()} | {acc.account_id}</div>
                          </div>
                        </label>
                      )
                    })}
                    <button
                      onClick={() => setSelAccts(
                        selAccts.size === accounts.length ? new Set() : new Set(accounts.map(a => a.id))
                      )}
                      style={{ fontSize: 8, background: 'none', border: `1px solid ${C.dim}`, color: C.dim, padding: '2px 8px', cursor: 'pointer', marginTop: 2, ...mono }}
                    >
                      {selAccts.size === accounts.length ? 'DESELECT ALL' : 'SELECT ALL'}
                    </button>
                  </div>

                  {/* Frameworks */}
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 10, color: C.dim, marginBottom: 10 }}>{'>> FRAMEWORK_SCOPE'}</div>
                    {FRAMEWORKS.map(fw => (
                      <label
                        key={fw.value}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer',
                          marginBottom: 6, padding: '5px 8px',
                          background: selFw === fw.value ? `${C.purple}18` : 'rgba(255,255,255,0.02)',
                          border: `1px solid ${selFw === fw.value ? C.purple + '55' : 'rgba(255,255,255,0.08)'}`,
                          borderRadius: 3, transition: 'all 0.15s',
                        }}
                      >
                        <input
                          type="radio"
                          name="multi-fw"
                          checked={selFw === fw.value}
                          onChange={() => setSelFw(fw.value)}
                          style={{ accentColor: C.purple, width: 12, height: 12 }}
                        />
                        <span style={{ fontSize: 10, color: selFw === fw.value ? C.purple : C.dim, fontWeight: selFw === fw.value ? 800 : 400 }}>
                          {fw.label}
                        </span>
                      </label>
                    ))}
                  </div>
                </div>

                {/* Summary line */}
                <div style={{ fontSize: 9, color: C.dim, marginBottom: 10 }}>
                  {selAccts.size > 0
                    ? `Will trigger ${selAccts.size} scan${selAccts.size > 1 ? 's' : ''} (${selAccts.size} x ${selFw.toUpperCase()})`
                    : 'Select at least one account'}
                </div>

                <button
                  onClick={handleMultiTrigger}
                  disabled={triggering || refreshing || selAccts.size === 0}
                  style={{
                    width: '100%',
                    background: selAccts.size === 0 ? 'none'
                      : triggering || refreshing ? 'var(--color-surface-3)'
                      : `${C.green}22`,
                    border: `1px solid ${selAccts.size === 0 ? 'rgba(255,255,255,0.1)' : triggering || refreshing ? 'var(--color-surface-3)' : C.green}`,
                    color: selAccts.size === 0 ? C.dim : triggering || refreshing ? C.dim : C.green,
                    padding: '11px', fontWeight: 900, fontSize: 11, ...mono,
                    cursor: selAccts.size === 0 || triggering || refreshing ? 'not-allowed' : 'pointer',
                    borderRadius: 2, transition: 'all 0.2s',
                  }}
                >
                  {triggering
                    ? '>> INITIATING_SCANS...'
                    : refreshing
                      ? '>> SCANS_IN_PROGRESS...'
                      : selAccts.size === 0
                        ? '>> SELECT AN ACCOUNT'
                        : `>> SCAN ${selAccts.size} ACCOUNT${selAccts.size > 1 ? 'S' : ''} [${selFw.toUpperCase()}]`}
                </button>
              </div>
            )}
          </div>
        </TerminalWindow>

        {/* ── Scan history table ── */}
        <TerminalWindow title="scan_history_buffer.log">
          <div style={{ overflowX: 'auto', maxHeight: '500px' }}>
            <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse', ...mono, fontSize: 11 }}>
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
                {/* Optimistic RUNNING row while scan is in-flight */}
                {refreshing && !scans.find(s => s.id > maxIdRef.current) && (
                  <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(245,158,11,0.06)' }}>
                    <td style={{ padding: '10px 4px', color: 'var(--color-warning)' }}>0x----</td>
                    <td style={{ padding: '10px 4px' }}>{new Date().toISOString().split('T')[0]}</td>
                    <td style={{ padding: '10px 4px', color: 'var(--color-accent)' }}>
                      {mode === 'single'
                        ? accounts.find(a => a.id === parseInt(form.account_id))?.name || `ACC_${form.account_id}`
                        : `${selAccts.size} ACCOUNTS`}
                    </td>
                    <td style={{ padding: '10px 4px' }}>{(mode === 'single' ? form.framework : selFw).toUpperCase()}</td>
                    <td style={{ padding: '10px 4px', color: 'var(--color-warning)' }}>--.--%</td>
                    <td style={{ padding: '10px 4px', color: 'var(--color-warning)' }}>[RUNNING]</td>
                  </tr>
                )}

                {scans.length === 0 && !refreshing ? (
                  <tr>
                    <td colSpan="6" style={{ textAlign: 'center', padding: '40px', color: 'var(--color-text-dim)' }}>
                      [ NO_RECORDS_FOUND ]
                    </td>
                  </tr>
                ) : scans.map(scan => {
                  const status = scanStatus(scan)
                  const isCompleted = status === 'completed'
                  const score = scan.compliance_score || 0
                  return (
                    <tr
                      key={scan.id}
                      style={{
                        borderBottom: '1px solid rgba(255,255,255,0.03)',
                        background: !isCompleted ? 'rgba(245,158,11,0.04)' : 'transparent'
                      }}
                    >
                      <td style={{ padding: '10px 4px', color: 'var(--color-text-dim)' }}>
                        0x{(scan.id || 0).toString(16).padStart(4, '0')}
                      </td>
                      <td style={{ padding: '10px 4px' }}>
                        {scan.started_at ? new Date(scan.started_at).toISOString().replace('T', ' ').slice(0, 16) : 'N/A'}
                      </td>
                      <td style={{ padding: '10px 4px', color: 'var(--color-accent)' }}>
                        {accounts.find(a => a.id === scan.account_id)?.name || `ACC_${scan.account_id}`}
                      </td>
                      <td style={{ padding: '10px 4px' }}>{scan.framework?.toUpperCase() || 'ALL'}</td>
                      <td style={{ padding: '10px 4px', fontWeight: 900, color: isCompleted ? (score >= 80 ? 'var(--color-success)' : 'var(--color-danger)') : 'var(--color-warning)' }}>
                        {isCompleted ? `${score.toFixed(1)}%` : '--.--%'}
                      </td>
                      <td style={{ padding: '10px 4px', color: isCompleted ? 'var(--color-success)' : 'var(--color-warning)' }}>
                        [{status.toUpperCase()}]
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </TerminalWindow>
      </div>
    </div>
  )
}
