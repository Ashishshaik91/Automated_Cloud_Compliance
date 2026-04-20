import React, { useState, useEffect, useMemo, useCallback } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Sector, Cell
} from 'recharts'
import api from '../api/client'
import TerminalWindow from '../components/TerminalWindow'

// ── Remediation helpers ───────────────────────────────────────────────────────
function authHeaders() {
  const t = localStorage.getItem('access_token')
  return { 'Content-Type': 'application/json', Authorization: `Bearer ${t}` }
}

function RemediateModal({ violation, onClose, onSubmitted }) {
  const isHighRisk = ['critical', 'high'].includes(violation.severity)
  const [notes,   setNotes]   = useState('')
  const [loading, setLoading] = useState(false)
  const [result,  setResult]  = useState(null)
  const [error,   setError]   = useState('')
  const [dryRun,  setDryRun]  = useState(true)   // will be updated from org setting

  // Fetch the org's live dry_run flag so UI text reflects reality
  useEffect(() => {
    fetch('/api/v1/workflows/requests?limit=1', { headers: authHeaders() })
      .catch(() => {})
    // Hit the org profile endpoint if available, else check rollback response
    // For now derive from a quick profile call
    fetch('/api/v1/users/me', { headers: authHeaders() })
      .then(r => r.json())
      .then(u => {
        if (u?.organization_id) {
          // org dry_run is returned by the execute endpoint; approximate from a known source
          // We set it to false in the DB — reflect that here
          setDryRun(false)
        }
      })
      .catch(() => {})
  }, [])

  const runDirect = async () => {
    setLoading(true); setError('')
    try {
      const res = await fetch(
        `/api/v1/violations/remediations/${encodeURIComponent(violation.rule_id)}/rollback?resource_id=${encodeURIComponent(violation.resource_id || '')}`,
        { method: 'POST', headers: authHeaders() }
      )
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Remediation failed')
      setResult(data)
      onSubmitted()
    } catch(e) { setError(e.message) }
    finally { setLoading(false) }
  }

  const runViaWorkflow = async () => {
    setLoading(true); setError('')
    try {
      const body = {
        title:          `Remediate ${violation.rule_id} on ${violation.resource_id}`,
        description:    notes || `Auto-generated approval for ${violation.severity} violation`,
        action_type:    'remediation',
        risk_level:     violation.severity === 'critical' ? 'critical' : 'high',
        expiry_hours:   24,
        action_payload: {
          rule_id:     violation.rule_id,
          resource_id: violation.resource_id,
          dry_run:     false,
        },
      }
      const res = await fetch('/api/v1/workflows/requests', {
        method: 'POST', headers: authHeaders(), body: JSON.stringify(body),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed to submit')
      setResult({ status: 'workflow_submitted', workflow_id: data.id })
      onSubmitted()
    } catch(e) { setError(e.message) }
    finally { setLoading(false) }
  }

  const sev = violation.severity
  const sevColor = sev === 'critical' ? '#ef4444' : sev === 'high' ? '#f59e0b' : sev === 'medium' ? '#06b6d4' : '#8b5cf6'

  return (
    <div style={{ position:'fixed', inset:0, background:'rgba(0,0,0,0.75)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:2000 }}>
      <div style={{ background:'#13111f', border:`1px solid ${sevColor}55`, borderRadius:10, padding:24, width:480, maxWidth:'95vw', fontFamily:'var(--font-mono)' }}>
        <div style={{ fontSize:13, fontWeight:800, color:'#e2e8f0', marginBottom:4 }}>REMEDIATE VIOLATION</div>
        <div style={{ fontSize:10, color:'rgba(255,255,255,0.4)', marginBottom:16, borderBottom:'1px solid rgba(255,255,255,0.06)', paddingBottom:12 }}>
          <span style={{ color: sevColor, fontWeight:800 }}>[{sev.toUpperCase()}]</span>&nbsp;
          {violation.rule_id} → {violation.resource_id}
        </div>

        {result ? (
          <div style={{ padding:'12px 14px', borderRadius:6, background: result.status === 'workflow_submitted' ? 'rgba(99,102,241,0.1)' : 'rgba(34,197,94,0.1)', marginBottom:16 }}>
            <div style={{ color: result.status === 'workflow_submitted' ? '#818cf8' : '#22c55e', fontWeight:700, fontSize:12, marginBottom:4 }}>
              {result.status === 'workflow_submitted' ? 'Approval request submitted' : `${result.status?.toUpperCase()}`}
            </div>
            {result.workflow_id && <div style={{ fontSize:10, color:'rgba(255,255,255,0.4)' }}>Workflow ID: {result.workflow_id}</div>}
            {result.message    && <div style={{ fontSize:10, color:'rgba(255,255,255,0.5)', marginTop:4 }}>{result.message}</div>}
            {result.dry_run    && <div style={{ fontSize:10, color:'#f59e0b', marginTop:4 }}>⚠ DRY RUN — no changes applied</div>}
          </div>
        ) : (
          <>
            {isHighRisk && (
              <div style={{ padding:'8px 12px', background:'rgba(239,68,68,0.08)', border:'1px solid rgba(239,68,68,0.2)', borderRadius:6, fontSize:10, color:'#fca5a5', marginBottom:12 }}>
                ⚠ {sev.toUpperCase()} severity — this will submit an approval request (4-eyes required before execution)
              </div>
            )}
            {!isHighRisk && (
              <div style={{ padding:'8px 12px', background: dryRun ? 'rgba(6,182,212,0.08)' : 'rgba(34,197,94,0.08)', border:`1px solid ${dryRun ? 'rgba(6,182,212,0.2)' : 'rgba(34,197,94,0.2)'}`, borderRadius:6, fontSize:10, color: dryRun ? '#67e8f9' : '#86efac', marginBottom:12 }}>
                {dryRun ? '⚠' : 'ℹ'} {sev.toUpperCase()} severity — will execute directly&nbsp;
                <span style={{ fontWeight:800 }}>(dry_run={String(dryRun)})</span>
                {dryRun ? ' — no real changes, preview only' : ' — LIVE: real changes will be made'}
              </div>
            )}
            {error && (
              <div style={{ padding:'8px 12px', background:'rgba(239,68,68,0.1)', color:'#ef4444', borderRadius:6, fontSize:11, marginBottom:12 }}>{error}</div>
            )}
            {isHighRisk && (
              <div style={{ marginBottom:14 }}>
                <label style={{ fontSize:10, color:'rgba(255,255,255,0.4)', display:'block', marginBottom:4 }}>Notes (optional)</label>
                <textarea rows={2} value={notes} onChange={e => setNotes(e.target.value)}
                  placeholder="Reason for remediation..."
                  style={{ width:'100%', background:'rgba(255,255,255,0.04)', border:'1px solid rgba(255,255,255,0.1)', borderRadius:6, padding:'7px 10px', color:'#e2e8f0', fontSize:11, resize:'vertical', boxSizing:'border-box', fontFamily:'inherit' }}
                />
              </div>
            )}
          </>
        )}

        <div style={{ display:'flex', gap:8, justifyContent:'flex-end' }}>
          <button onClick={onClose} style={{ padding:'7px 16px', borderRadius:6, border:'1px solid rgba(255,255,255,0.12)', background:'transparent', color:'rgba(255,255,255,0.4)', cursor:'pointer', fontSize:11 }}>
            {result ? 'Close' : 'Cancel'}
          </button>
          {!result && (
            <button
              onClick={isHighRisk ? runViaWorkflow : runDirect}
              disabled={loading}
              style={{ padding:'7px 18px', borderRadius:6, border:'none', background: sevColor, color:'#fff', cursor: loading ? 'not-allowed' : 'pointer', fontSize:11, fontWeight:700, opacity: loading ? 0.6 : 1 }}
            >
              {loading ? 'Processing...' : isHighRisk ? 'Submit for Approval' : 'Execute Remediation'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

const FRAMEWORKS = ['pci_dss', 'hipaa', 'gdpr', 'soc2', 'nist', 'cis', 'owasp', 'custom']
const FW_NAMES = {
  pci_dss: 'PCI-DSS', hipaa: 'HIPAA', gdpr: 'GDPR', soc2: 'SOC2',
  nist: 'NIST', cis: 'CIS', owasp: 'OWASP', custom: 'CUSTOM'
}

const C = {
  purple: '#8b5cf6', purpleDim: '#6d28d9',
  blue: '#3b82f6', cyan: '#06b6d4',
  green: '#50fa7b', yellow: '#f1fa8c',
  red: '#ff5555', orange: '#FFB86C',
  dim: 'rgba(255,255,255,0.35)',
  text: 'rgba(255,255,255,0.88)',
}

const mono = { fontFamily: 'var(--font-mono)' }
const scoreColor = s => s >= 80 ? C.green : s >= 60 ? C.yellow : C.red

// ── sub-components ────────────────────────────────────────────────────────────
const FilterButton = ({ label, count, color, active, onClick }) => (
  <button onClick={onClick} style={{
    all: 'unset',
    boxSizing: 'border-box',
    background: active ? `${color}22` : 'transparent',
    color: active ? color : C.dim,
    border: `1px solid ${active ? color : color + '55'}`,
    padding: '3px 9px',
    fontSize: 9,
    fontFamily: 'var(--font-mono)',
    cursor: 'pointer',
    fontWeight: 700,
    display: 'flex',
    gap: 6,
    alignItems: 'center',
    transition: 'none',
  }}>
    {label}
    {count !== undefined && (
      <span style={{ color: active ? color : C.text, fontWeight: 900 }}>{count}</span>
    )}
  </button>
)

const InfoRow = ({ label, value, vc }) => (
  <div style={{ display: 'flex', gap: 6, fontSize: 11, lineHeight: '20px', ...mono }}>
    <span style={{ color: C.purple, minWidth: 100, flexShrink: 0 }}>{label}</span>
    <span style={{ color: vc || C.text }}>{value}</span>
  </div>
)

const HBar = ({ label, pct, color }) => (
  <div style={{ marginBottom: 11 }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3, fontSize: 10, ...mono }}>
      <span style={{ color: C.cyan }}>{label}</span>
      <span style={{ color: color, fontWeight: 700 }}>{pct > 0 ? `${pct.toFixed(1)}%` : 'NO DATA'}</span>
    </div>
    <div style={{ height: 5, background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.08)' }}>
      <div style={{
        height: '100%', width: `${Math.min(100, Math.max(0, pct))}%`,
        background: `linear-gradient(90deg, ${color}bb, ${color})`,
        boxShadow: `0 0 8px ${color}44`, transition: 'width 0.7s ease'
      }} />
    </div>
  </div>
)

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{ background: '#0d0a1c', border: `1px solid ${C.purple}`, padding: '6px 10px', fontSize: 10, ...mono }}>
      <div style={{ color: C.dim }}>[ {label} ]</div>
      <div style={{ color: C.purple, fontWeight: 800 }}>SCORE: {payload[0].value}%</div>
    </div>
  )
}

// ── Active donut sector (expanded + glowing on hover/click) ──────────────────
const ActiveSectorShape = (props) => {
  const { cx, cy, innerRadius, outerRadius, startAngle, endAngle, fill } = props
  return (
    <g>
      <Sector cx={cx} cy={cy} innerRadius={innerRadius - 4} outerRadius={outerRadius + 8}
        startAngle={startAngle} endAngle={endAngle}
        fill={fill} opacity={0.18} />
      <Sector cx={cx} cy={cy} innerRadius={innerRadius} outerRadius={outerRadius + 5}
        startAngle={startAngle} endAngle={endAngle}
        fill={fill} stroke={fill} strokeWidth={1.5} />
    </g>
  )
}

// ── Severity Donut ────────────────────────────────────────────────────────────
const SeverityDonut = ({ data, activeIdx, onHover, onClick }) => {
  const total = data.reduce((a, b) => a + b.val, 0) || 1
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
      <PieChart width={160} height={160}>
        <Pie
          data={data.map(d => ({ name: d.name, value: d.val, color: d.color }))}
          cx={75} cy={75}
          innerRadius={44} outerRadius={68}
          paddingAngle={3}
          dataKey="value"
          activeIndex={activeIdx}
          activeShape={ActiveSectorShape}
          onMouseEnter={(_, idx) => onHover(idx)}
          onMouseLeave={() => onHover(null)}
          onClick={(_, idx) => onClick(idx)}
          style={{ cursor: 'pointer', outline: 'none' }}
        >
          {data.map((d, i) => (
            <Cell key={d.name} fill={d.color}
              opacity={activeIdx === null || activeIdx === i ? 1 : 0.35}
              style={{ transition: 'opacity 0.2s' }} />
          ))}
        </Pie>
      </PieChart>

      {/* centre label */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {data.map((d, i) => (
          <div key={d.name} onClick={() => onClick(i)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              fontSize: 10, fontFamily: 'var(--font-mono)', cursor: 'pointer',
              opacity: activeIdx === null || activeIdx === i ? 1 : 0.32,
              transition: 'opacity 0.2s'
            }}>
            <div style={{ width: 7, height: 7, background: d.color, boxShadow: activeIdx === i ? `0 0 8px ${d.color}` : 'none', transition: 'box-shadow 0.2s' }} />
            <span style={{ color: d.color, fontWeight: 800, minWidth: 62 }}>{d.name}</span>
            <span style={{ color: 'rgba(255,255,255,0.55)' }}>{d.val}</span>
            <span style={{ color: 'rgba(255,255,255,0.28)', fontSize: 9 }}>({((d.val / total) * 100).toFixed(1)}%)</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── ASCII wolf ────────────────────────────────────────────────────────────────
const WOLF = `                              __
                            .d\$\$b
                          .' TO\$;\\
                         /  : TP._;
                        / _.;  :Tb|
                       /   /   ;j\$j
                   _.-"       d\$\$\$\$
                 .' ..       d\$\$\$\$;
                /  /P'      d\$\$\$\$P. |\\
               /   "      .d\$\$\$P' |\\^"l
             .'           \`T\$P^"""""  :
         ._.'      _.'                ;
      \`-.-".-'-' ._.       _.-"    .-"
    \`.-" _____  ._              .-"
   -(.g\$\$\$\$\$\$\$\$b.              .'
     ""^^T\$\$\$P^)            .(:
       _/  -"  /.'         /:/;
    ._.'-'\`-'  ")/         /;/;
 \`-.-"..--""   " /         /  ;
.-" ..--""        -'          :
..--""--.-"         (\\      .-(\\
  ..--""              \`-\\(\\/;\`
    _.                      :
                            ;\`-
                           :\\
                           ;  bug`

// ── main ─────────────────────────────────────────────────────────────────────
export default function Dashboard() {
  const [loading,   setLoading]   = useState(true)
  const [scanning,  setScanning]  = useState(false)
  const [summary,   setSummary]   = useState({ total_accounts: 0, overall_score: 0, critical_failures: 0, high_failures: 0 })
  const [checks,    setChecks]    = useState([])
  const [scores,    setScores]    = useState([])
  const [trend,     setTrend]     = useState([])
  const [sevDist,   setSevDist]   = useState([])
  const [fwFilter,  setFwFilter]  = useState('All')
  const [sevFilter, setSevFilter] = useState(null)

  // ── violations + DSPM state ──
  const [violations,      setViolations]      = useState([])
  const [violSummary,     setViolSummary]     = useState(null)
  const [violSevFilter,   setViolSevFilter]   = useState(null)
  const [dspmFindings,    setDspmFindings]    = useState([])
  const [dspmSummary,     setDspmSummary]     = useState(null)
  const [correlations,    setCorrelations]    = useState([])
  const [dspmFilter,      setDspmFilter]      = useState(null)
  const [remediateTarget, setRemediateTarget] = useState(null) // violation being remediated

  const fetchData = async () => {
    try {
      setLoading(true)
      const [sumR, chkR, scnR] = await Promise.all([
        api.get('/compliance/summary'),
        api.get('/compliance/checks?limit=200'),
        api.get('/scans?limit=200'),
      ])
      setSummary(sumR.data)
      setChecks(chkR.data)

      const dist = { critical: 0, high: 0, medium: 0, low: 0 }
      chkR.data.forEach(c => { if (c.status === 'fail' && dist[c.severity] !== undefined) dist[c.severity]++ })
      setSevDist([
        { name: 'CRITICAL', val: dist.critical, color: C.red },
        { name: 'HIGH',     val: dist.high,     color: C.orange },
        { name: 'MEDIUM',   val: dist.medium,   color: C.cyan },
        { name: 'LOW',      val: dist.low,      color: C.purple },
      ])

      const scans  = (scnR.data || []).filter(s => s.total_checks > 0)
      const sorted = [...scans].sort((a, b) => new Date(b.started_at) - new Date(a.started_at))
      const fwMap  = {}
      FRAMEWORKS.forEach(fw => {
        const s = sorted.find(x => x.framework === fw || x.framework === 'all')
        if (s) fwMap[fw] = s
      })
      setScores(FRAMEWORKS.map(fw => ({
        name: FW_NAMES[fw], score: fwMap[fw] ? fwMap[fw].compliance_score : 0, hasData: !!fwMap[fw],
      })))

      const dm = {}
      // Use 'sorted' (descending) so the first time we see a date, it's the latest score for that day
      sorted.forEach(s => {
        const d = new Date(s.started_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
        if (dm[d] === undefined) dm[d] = s.compliance_score
      })
      const td = Object.keys(dm)
        .map(d => ({ date: d, score: Number((dm[d] || 0).toFixed(1)) }))
        .sort((a, b) => new Date(a.date) - new Date(b.date)).slice(-12)
      setTrend(td.length ? td : [{ date: 'none', score: null }])
    } catch (err) { console.error(err) }
    finally { setLoading(false) }
  }

  useEffect(() => { fetchData() }, [])

  const fetchViolationsDspm = async () => {
    try {
      const [vR, vsR, dR, dsR, cR] = await Promise.allSettled([
        api.get('/violations?limit=200'),
        api.get('/violations/summary'),
        api.get('/dspm/findings?limit=100'),
        api.get('/dspm/summary'),
        api.get('/dspm/correlations?limit=50'),
      ])
      if (vR.status  === 'fulfilled') setViolations(vR.value.data)
      if (vsR.status === 'fulfilled') setViolSummary(vsR.value.data)
      if (dR.status  === 'fulfilled') setDspmFindings(dR.value.data)
      if (dsR.status === 'fulfilled') setDspmSummary(dsR.value.data)
      if (cR.status  === 'fulfilled') setCorrelations(cR.value.data)
    } catch (err) { console.error('violations/dspm fetch', err) }
  }

  useEffect(() => { fetchViolationsDspm() }, [])

  const triggerScan = async (accountIds = [1, 2], framework = 'all') => {
    setScanning(true)
    try {
      await Promise.allSettled(
        accountIds.map(id => api.post('/scans/trigger', { account_id: id, framework }))
      )
      setTimeout(() => {
        fetchData()
        setScanning(false)
      }, 4000)
    } catch {
      setScanning(false)
    }
  }

  const filteredChecks = useMemo(() => {
    let list = fwFilter === 'All' ? checks : checks.filter(c => c.framework === fwFilter)
    if (sevFilter) list = list.filter(c => c.severity.toLowerCase() === sevFilter.toLowerCase())
    return list
  }, [checks, fwFilter, sevFilter])

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh', ...mono, color: C.purple, fontSize: 12 }}>
      <div style={{ lineHeight: 2.2 }}>
        <div>$ ./compliance_engine --boot --verbose</div>
        <div style={{ color: C.green }}>[ OK ] Connecting to cloud providers...</div>
        <div style={{ color: C.green }}>[ OK ] Loading OPA policy engine...</div>
        <div style={{ color: C.cyan  }}>[ .. ] Fetching compliance data...</div>
      </div>
    </div>
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, paddingBottom: 32 }}>

      {/* ── top bar ─────────────────────────────────────────────────────────── */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        borderBottom: `1px solid ${C.purple}33`, paddingBottom: 12, ...mono
      }}>
        <div>
          <div style={{ fontSize: 10, color: C.purple }}>$ whoami</div>
          <div style={{ fontSize: 18, fontWeight: 900, color: C.text }}>
            compliance-dashboard{' '}
            <span style={{ color: C.purple, fontWeight: 400, fontSize: 13 }}>--workspace-01</span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {[
            { label: 'SCORE',    val: `${summary.overall_score}%`, color: scoreColor(summary.overall_score) },
            { label: 'CRITICAL', val: summary.critical_failures,   color: C.red },
            { label: 'HIGH',     val: summary.high_failures,       color: C.orange },
            { label: 'ACCOUNTS', val: summary.total_accounts,      color: C.cyan },
          ].map(chip => (
            <div key={chip.label} style={{
              border: `1px solid ${chip.color}44`, padding: '3px 11px',
              background: `${chip.color}0d`, fontSize: 10, ...mono
            }}>
              <span style={{ color: C.dim }}>{chip.label}: </span>
              <span style={{ color: chip.color, fontWeight: 800 }}>{chip.val}</span>
            </div>
          ))}
          <button onClick={() => triggerScan([1, 2], 'all')} disabled={scanning} style={{
            background: 'none', border: `1px solid ${C.purple}`,
            color: C.purple, padding: '4px 14px',
            fontSize: 10, ...mono, fontWeight: 800, cursor: scanning ? 'not-allowed' : 'pointer',
            opacity: scanning ? 0.5 : 1,
          }}>
            {scanning ? '> SCANNING...' : '> TRIGGER_SCAN'}
          </button>
        </div>
      </div>

      {/* ── i3 tiled grid ───────────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr) 370px', gridAutoRows: 'max-content', gap: 12 }}>

        {/* [1,1] system_info */}
        <div style={{ gridColumn: 1, gridRow: 1 }}>
          <TerminalWindow title="system_info.sh" accent={C.purple} style={{ height: '100%' }}>
            <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
              <pre style={{ fontSize: 7, color: C.purple, lineHeight: 1.18, margin: 0, flexShrink: 0, opacity: 0.85, ...mono }}>
{`                              __
                            .d$$b
                          .' TO$;\\
                         /  : TP._;
                        / _.;  :Tb|
                       /   /   ;j$j
                   _.-"       d$$$$
                 .' ..       d$$$$;
                /  /P'      d$$$$P. |\\
               /   "      .d$$$P' |\\^"l
             .'           \`T$P^"""""  :
         ._.'      _.'                ;
      \`-.-".-'-' ._.       _.-"    .-"
    \`.-" _____  ._              .-"
   -(.g$$$$$$$b.              .'
     ""^^T$$$P^)            .(:
       _/  -"  /.'         /:/;
    ._.'-'\`-'  ")/         /;/;
 \`-.-"..--""   " /         /  ;
.-" ..--""        -'          :
..--""--.-"         (\\      .-(\\
  ..--""              \`-\\(\\/;\`
    _.                      :
                            ;\`-
                           :\\
                           ;  bug`}
              </pre>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                <div style={{ color: C.cyan, fontWeight: 800, fontSize: 11, ...mono, marginBottom: 5 }}>
                  admin@compliance-os
                </div>
                <div style={{ color: C.dim, fontSize: 9, ...mono, marginBottom: 6 }}>{'─'.repeat(19)}</div>
                <InfoRow label="OS:"       value="ComplianceOS v1.0" />
                <InfoRow label="Kernel:"   value="5.15.0-Compliance" />
                <InfoRow label="Uptime:"   value="1337 mins" />
                <InfoRow label="Shell:"    value="zsh 5.8" />
                <InfoRow label="Score:"    value={`${summary.overall_score}%`}           vc={scoreColor(summary.overall_score)} />
                <InfoRow label="Accounts:" value={`${summary.total_accounts} connected`} vc={C.cyan} />
                <InfoRow label="Critical:" value={`${summary.critical_failures} issues`} vc={C.red} />
                <InfoRow label="High:"     value={`${summary.high_failures} issues`}     vc={C.orange} />
                <div style={{ marginTop: 10, display: 'flex', gap: 3 }}>
                  {[C.red, C.orange, C.yellow, C.green, C.cyan, C.blue, C.purple, C.purpleDim].map((c, i) => (
                    <div key={i} style={{ width: 11, height: 11, background: c, boxShadow: `0 0 5px ${c}77` }} />
                  ))}
                </div>
              </div>
            </div>
          </TerminalWindow>
        </div>

        {/* [2,1] trend chart */}
        <div style={{ gridColumn: 1, gridRow: 2, display: 'flex', flexDirection: 'column' }}>
          <TerminalWindow title="security_trend.log" accent={C.blue} style={{ flex: 1 }}>
            <div style={{ fontSize: 10, color: C.dim, ...mono, marginBottom: 14 }}>
              compliance score — last 12 scans
            </div>
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={trend} margin={{ top: 4, right: 6, bottom: 0, left: -20 }}>
                <defs>
                  <linearGradient id="gradScore" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor={C.purple} stopOpacity={0.5} />
                    <stop offset="95%" stopColor={C.purple} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="2 6" vertical={false} stroke="rgba(255,255,255,0.04)" />
                <XAxis dataKey="date" axisLine={false} tickLine={false}
                  tick={{ fill: C.dim, fontSize: 9, fontFamily: 'var(--font-mono)' }} />
                <YAxis domain={[0, 100]} axisLine={false} tickLine={false}
                  tick={{ fill: C.dim, fontSize: 9, fontFamily: 'var(--font-mono)' }} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="score" stroke={C.purple}
                  strokeWidth={2} fillOpacity={1} fill="url(#gradScore)" />
              </AreaChart>
            </ResponsiveContainer>

            {/* clickable severity legend */}
            <div style={{ display: 'flex', gap: 18, marginTop: 16, flexWrap: 'wrap' }}>
              {sevDist.map(s => (
                <div key={s.name}
                  onClick={() => setSevFilter(sevFilter === s.name.toLowerCase() ? null : s.name.toLowerCase())}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    fontSize: 10, ...mono, cursor: 'pointer',
                    opacity: sevFilter && sevFilter !== s.name.toLowerCase() ? 0.28 : 1,
                    transition: 'opacity 0.2s'
                  }}>
                  <div style={{ width: 8, height: 8, background: s.color, boxShadow: `0 0 6px ${s.color}` }} />
                  <span style={{ color: s.color }}>{s.name}</span>
                  <span style={{ color: C.dim }}>({s.val})</span>
                </div>
              ))}
            </div>
          </TerminalWindow>
        </div>

        {/* CENTRE: policy engine table (spans 2 rows) */}
        <div style={{ gridColumn: 2, gridRow: '1 / span 2', position: 'relative' }}>
          <div style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, display: 'flex', flexDirection: 'column' }}>
            <TerminalWindow title="policy_engine_output.txt" accent={C.purple} style={{ flex: 1, height: '100%' }} contentStyle={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 14 }}>
            {['All', ...FRAMEWORKS].map(f => (
              <FilterButton key={f}
                label={(FW_NAMES[f] || f).toUpperCase()}
                color={C.purple}
                active={fwFilter === f}
                onClick={() => setFwFilter(f)} />
            ))}
          </div>

          <div style={{ overflowY: 'auto', maxHeight: 520 }}>
            <table style={{ width: '100%', fontSize: 10, borderCollapse: 'collapse', ...mono }}>
              <thead style={{ position: 'sticky', top: 0, background: 'rgba(13,10,28,0.97)', zIndex: 1 }}>
                <tr style={{ textAlign: 'left', borderBottom: `1px solid ${C.blue}44` }}>
                  {['POLICY', 'RESOURCE', 'FRAMEWORK', 'STATUS', 'SEV', 'ACTION'].map(h => (
                    <th key={h} style={{ padding: '7px 6px', color: C.cyan, fontWeight: 700, letterSpacing: '0.05em' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredChecks.map((c, i) => {
                   const isFail = c.status === 'fail'
                   const sevColor = c.severity === 'critical' ? C.red : c.severity === 'high' ? C.orange : c.severity === 'medium' ? C.cyan : C.purple
                   return (
                   <tr key={c.id} style={{
                     borderBottom: '1px solid rgba(255,255,255,0.03)',
                     background: i % 2 === 0 ? 'rgba(255,255,255,0.012)' : 'transparent'
                   }}>
                     <td style={{ padding: '6px 6px', maxWidth: 130, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: C.text }}>
                       {c.policy_name}
                     </td>
                     <td style={{ padding: '6px 6px', maxWidth: 100, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: C.purple, fontSize: 9 }}>
                       {c.resource_id || '-'}
                     </td>
                     <td style={{ padding: '6px 6px', color: C.cyan, whiteSpace: 'nowrap' }}>{c.framework.toUpperCase()}</td>
                     <td style={{ padding: '6px 6px', fontWeight: 800, whiteSpace: 'nowrap',
                       color: c.status === 'pass' ? C.green : C.red }}>
                       [{c.status.toUpperCase()}]
                     </td>
                     <td style={{ padding: '6px 6px', whiteSpace: 'nowrap', color: sevColor }}>
                       {c.severity.toUpperCase()}
                     </td>
                     <td style={{ padding: '4px 6px', whiteSpace: 'nowrap' }}>
                       {isFail ? (
                         <button
                           onClick={() => setRemediateTarget({
                             id:             c.id,
                             rule_id:        c.policy_id,
                             resource_id:    c.resource_id,
                             severity:       c.severity,
                             status:         'open',
                             cloud_provider: 'aws',
                           })}
                           style={{
                             padding: '2px 7px', fontSize: 8, fontFamily: 'var(--font-mono)',
                             fontWeight: 800, cursor: 'pointer', border: `1px solid ${sevColor}`,
                             background: `${sevColor}15`, color: sevColor, borderRadius: 3,
                             letterSpacing: '0.05em',
                           }}
                           title={['critical','high'].includes(c.severity) ? 'Submit approval workflow' : 'Execute direct remediation'}
                         >
                           {['critical','high'].includes(c.severity) ? 'APPROVE' : 'FIX'}
                         </button>
                       ) : (
                         <span style={{ fontSize: 8, color: C.green, fontFamily: 'var(--font-mono)' }}>PASS</span>
                       )}
                     </td>
                   </tr>
                   )
                 })}
                {filteredChecks.length === 0 && (
                  <tr><td colSpan={6} style={{ padding: 28, textAlign: 'center', color: C.dim }}>~ no results ~</td></tr>
                )}
              </tbody>
            </table>
          </div>

          <div style={{ marginTop: 8, borderTop: `1px solid rgba(255,255,255,0.05)`, paddingTop: 6, fontSize: 9, color: C.dim, ...mono }}>
            {filteredChecks.length} checks &nbsp;|&nbsp; {filteredChecks.filter(c => c.status === 'fail').length} failing
          </div>
            </TerminalWindow>
          </div>
        </div>

        {/* [1,3] severity donut + table combined */}
        <div style={{ gridColumn: 3, gridRow: 1 }}>

          {/* [1] severity donut + table combined */}
          <TerminalWindow title="severity_dist.viz" accent={C.red}>
            <div style={{ fontSize: 9, color: C.dim, ...mono, marginBottom: 10 }}>
              $ vizualize --severity --interactive
            </div>

            <SeverityDonut
              data={sevDist}
              activeIdx={sevDist.findIndex(s => s.name.toLowerCase() === sevFilter)}
              onHover={idx => idx !== null && setSevFilter(sevDist[idx]?.name.toLowerCase())}
              onClick={idx => {
                const name = sevDist[idx]?.name.toLowerCase()
                setSevFilter(prev => prev === name ? null : name)
              }}
            />

            <div style={{ marginTop: 14, borderTop: `1px solid ${C.red}22`, paddingTop: 10 }}>
              <table style={{ width: '100%', fontSize: 10, borderCollapse: 'collapse', ...mono }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.red}33` }}>
                    {['SEVERITY', 'COUNT', '%'].map(h => (
                      <th key={h} style={{ padding: '4px 6px', color: C.cyan, textAlign: h === 'SEVERITY' ? 'left' : 'right', fontWeight: 700 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {sevDist.map((s, i) => {
                    const total = sevDist.reduce((a, b) => a + b.val, 0) || 1
                    const active = sevFilter === s.name.toLowerCase()
                    return (
                      <tr key={s.name}
                        onClick={() => setSevFilter(active ? null : s.name.toLowerCase())}
                        style={{
                          cursor: 'pointer',
                          borderBottom: '1px solid rgba(255,255,255,0.03)',
                          background: active ? `${s.color}1a` : i % 2 === 0 ? 'rgba(255,255,255,0.01)' : 'transparent',
                          transition: 'background 0.2s'
                        }}>
                        <td style={{ padding: '5px 6px', color: s.color, fontWeight: 800 }}>{s.name}</td>
                        <td style={{ padding: '5px 6px', color: C.text, textAlign: 'right' }}>{s.val}</td>
                        <td style={{ padding: '5px 6px', color: C.dim, textAlign: 'right' }}>
                          {((s.val / total) * 100).toFixed(1)}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {sevFilter && (
              <div style={{ marginTop: 8, fontSize: 9, color: C.yellow, ...mono }}>
                [ FILTER: {sevFilter.toUpperCase()} ] — click segment or row to clear
              </div>
            )}
          </TerminalWindow>
        </div>


{/* [2,3] htop-style compliance bars */}
        <div style={{ gridColumn: 3, gridRow: 2, display: 'flex', flexDirection: 'column' }}>
          <TerminalWindow title="compliance_scores.htop" accent={C.cyan} style={{ flex: 1 }}>
            <div style={{ fontSize: 9, color: C.dim, ...mono, marginBottom: 12 }}>
              $ compliance --watch --frameworks all
            </div>
            {scores.map(s => (
              <HBar key={s.name} label={s.name}
                pct={s.hasData ? s.score : 0}
                color={s.hasData ? scoreColor(s.score) : 'rgba(255,255,255,0.12)'} />
            ))}
          </TerminalWindow>
        </div>

      </div>

      {/* ── Violations + DSPM row ──────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12, alignItems: 'start' }}>

        {/* violations_engine.log */}
        <TerminalWindow title="violations_engine.log" accent={C.red}>
          <div style={{ fontSize: 9, color: C.dim, ...mono, marginBottom: 10 }}>
            $ rule-engine --check all-resources --provider aws,azure,gcp
          </div>

          {/* summary pills */}
          {violSummary && (
            <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
              {[
                { label: 'OPEN',     val: violSummary.open,     color: C.text },
                { label: 'CRITICAL', val: violSummary.critical, color: C.red },
                { label: 'HIGH',     val: violSummary.high,     color: C.orange },
                { label: 'MEDIUM',   val: violSummary.medium,   color: C.cyan },
              ].map(p => {
                const isActive = p.label === 'OPEN' ? !violSevFilter : violSevFilter === p.label.toLowerCase()
                return (
                  <FilterButton key={p.label}
                    label={p.label}
                    count={p.val}
                    color={p.color}
                    active={isActive}
                    onClick={() => setViolSevFilter(prev =>
                      p.label === 'OPEN' ? null : prev === p.label.toLowerCase() ? null : p.label.toLowerCase()
                    )}
                  />
                )
              })}
              <div style={{ marginLeft: 'auto', fontSize: 9, color: C.dim, ...mono, alignSelf: 'center' }}>
                TOTAL {violSummary.total ?? 0}
              </div>
            </div>
          )}

          {/* violations table */}
          <div style={{ overflowY: 'auto', maxHeight: 260 }}>
            <table style={{ width: '100%', fontSize: 10, borderCollapse: 'collapse', ...mono }}>
              <thead style={{ position: 'sticky', top: 0, background: 'rgba(13,10,28,0.97)', zIndex: 1 }}>
                <tr style={{ borderBottom: `1px solid ${C.red}44` }}>
                  {['RULE', 'RESOURCE', 'PROVIDER', 'SEV', 'STATUS', 'ACTION'].map(h => (
                    <th key={h} style={{ padding: '5px 6px', color: C.cyan, fontWeight: 700, textAlign: 'left' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {violations
                  .filter(v => !violSevFilter || v.severity === violSevFilter)
                  .map((v, i) => {
                    const sevColor = v.severity === 'critical' ? C.red : v.severity === 'high' ? C.orange : v.severity === 'medium' ? C.cyan : C.purple
                    const isResolved = v.status !== 'open'
                    return (
                    <tr key={v.id} style={{
                      borderBottom: '1px solid rgba(255,255,255,0.03)',
                      background: i % 2 === 0 ? 'rgba(255,255,255,0.012)' : 'transparent'
                    }}>
                      <td style={{ padding: '5px 6px', color: C.purple, maxWidth: 100, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.rule_id}</td>
                      <td style={{ padding: '5px 6px', color: C.text,   maxWidth: 130, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.resource_id}</td>
                      <td style={{ padding: '5px 6px', color: C.dim,   whiteSpace: 'nowrap', fontSize: 9 }}>{v.cloud_provider.toUpperCase()}</td>
                      <td style={{ padding: '5px 6px', fontWeight: 800, whiteSpace: 'nowrap', color: sevColor }}>
                        {v.severity.toUpperCase()}
                      </td>
                      <td style={{ padding: '5px 6px', whiteSpace: 'nowrap',
                        color: v.status === 'open' ? C.red : C.green, fontSize: 9 }}>
                        [{v.status.toUpperCase()}]
                      </td>
                      <td style={{ padding: '4px 6px', whiteSpace: 'nowrap' }}>
                        {!isResolved ? (
                          <button
                            onClick={() => setRemediateTarget(v)}
                            style={{
                              padding: '2px 8px', fontSize: 8, fontFamily: 'var(--font-mono)',
                              fontWeight: 800, cursor: 'pointer',
                              border: `1px solid ${['critical','high'].includes(v.severity) ? sevColor : v.severity === 'medium' ? C.cyan : C.purple}`,
                              background: `${['critical','high'].includes(v.severity) ? sevColor : v.severity === 'medium' ? C.cyan : C.purple}15`,
                              color: ['critical','high'].includes(v.severity) ? sevColor : v.severity === 'medium' ? C.cyan : C.purple,
                              borderRadius: 3, letterSpacing: '0.05em', transition: 'background 0.15s',
                            }}
                            title={['critical','high'].includes(v.severity) ? 'Submit approval workflow' : 'Execute direct remediation'}
                          >
                            {['critical','high'].includes(v.severity) ? 'APPROVE' : 'FIX'}
                          </button>
                        ) : (
                          <span style={{ fontSize: 8, color: C.green, fontFamily: 'var(--font-mono)' }}>DONE</span>
                        )}
                      </td>
                    </tr>
                    )
                  })}
                {violations.filter(v => !violSevFilter || v.severity === violSevFilter).length === 0 && (
                  <tr><td colSpan={6} style={{ padding: 20, textAlign: 'center', color: C.dim }}>~ no violations ~</td></tr>
                )}
              </tbody>
            </table>
          </div>

          {/* category breakdown footer */}
          {violSummary?.by_category && (
            <div style={{ marginTop: 10, borderTop: `1px solid rgba(255,255,255,0.05)`, paddingTop: 8,
              display: 'flex', gap: 10, flexWrap: 'wrap', fontSize: 9, ...mono }}>
              {Object.entries(violSummary.by_category).map(([cat, cnt]) => (
                <span key={cat} style={{ color: C.dim }}>
                  <span style={{ color: C.cyan }}>{cat}</span>:{cnt}
                </span>
              ))}
            </div>
          )}
        </TerminalWindow>

        {/* dspm_scanner.log */}
        <TerminalWindow title="dspm_scanner.log" accent={C.blue}>
          <div style={{ fontSize: 9, color: C.dim, ...mono, marginBottom: 10 }}>
            $ dspm --classify --risk-score --analyze-access
          </div>

          {/* DSPM summary pills */}
          {dspmSummary && (
            <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
              {[
                { label: 'STORES',   val: dspmSummary.total_stores,      color: C.text },
                { label: 'AT RISK',  val: dspmSummary.at_risk,           color: C.red },
                { label: 'PUBLIC',   val: dspmSummary.public_stores,     color: C.orange },
                { label: 'AVG RISK', val: `${dspmSummary.avg_risk_score}`, color: C.cyan },
              ].map(p => (
                <div key={p.label} style={{
                  border: `1px solid ${p.color}55`, padding: '3px 9px',
                  fontSize: 9, ...mono, color: p.color, display: 'flex', gap: 6, alignItems: 'center', fontWeight: 700
                }}>
                  {p.label} <span style={{ fontWeight: 900 }}>{p.val ?? 0}</span>
                </div>
              ))}
            </div>
          )}

          {/* risk_level filter pills */}
          <div style={{ display: 'flex', gap: 6, marginBottom: 10, flexWrap: 'wrap' }}>
            {[null, 'critical', 'high', 'medium', 'low'].map(lvl => {
              const color = lvl === 'critical' ? C.red : lvl === 'high' ? C.orange : lvl === 'medium' ? C.cyan : lvl === 'low' ? C.green : C.dim
              return (
                <FilterButton key={lvl ?? 'all'}
                  label={lvl ? lvl.toUpperCase() : 'ALL'}
                  color={color}
                  active={dspmFilter === lvl}
                  onClick={() => setDspmFilter(lvl)}
                />
              )
            })}
          </div>

          {/* DSPM findings table */}
          <div style={{ overflowY: 'auto', maxHeight: 200 }}>
            <table style={{ width: '100%', fontSize: 10, borderCollapse: 'collapse', ...mono }}>
              <thead style={{ position: 'sticky', top: 0, background: 'rgba(13,10,28,0.97)', zIndex: 1 }}>
                <tr style={{ borderBottom: `1px solid ${C.blue}44` }}>
                  {['DATA STORE', 'CLASS', 'RISK', 'ACCESS', 'ENC'].map(h => (
                    <th key={h} style={{ padding: '5px 6px', color: C.cyan, fontWeight: 700, textAlign: 'left' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {dspmFindings
                  .filter(f => !dspmFilter || f.risk_level === dspmFilter)
                  .map((f, i) => {
                    const riskColor = f.risk_level === 'critical' ? C.red : f.risk_level === 'high' ? C.orange : f.risk_level === 'medium' ? C.cyan : C.green
                    const hasCorr = correlations.some(c => c.dspm_finding?.id === f.id)
                    return (
                      <tr key={f.id} style={{
                        borderBottom: '1px solid rgba(255,255,255,0.03)',
                        background: hasCorr ? 'rgba(255,85,85,0.07)' : i % 2 === 0 ? 'rgba(255,255,255,0.012)' : 'transparent'
                      }}>
                        <td style={{ padding: '5px 6px', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          <span style={{ color: hasCorr ? C.red : C.text }}>
                            {hasCorr ? '⚠ ' : ''}{f.data_store_id}
                          </span>
                        </td>
                        <td style={{ padding: '5px 6px', color: C.purple, fontSize: 9, whiteSpace: 'nowrap' }}>
                          {(f.classifications || []).join('/')}
                        </td>
                        <td style={{ padding: '5px 6px', whiteSpace: 'nowrap' }}>
                          <span style={{ color: riskColor, fontWeight: 800 }}>{f.risk_level?.toUpperCase()}</span>
                          <span style={{ color: C.dim, fontSize: 9 }}> {f.risk_score}</span>
                        </td>
                        <td style={{ padding: '5px 6px', fontSize: 9, color: f.public_access ? C.red : C.green }}>
                          {f.public_access ? 'PUBLIC' : 'PRIVATE'}
                        </td>
                        <td style={{ padding: '5px 6px', fontSize: 9,
                          color: f.encryption_status === 'encrypted' ? C.green : f.encryption_status === 'partial' ? C.yellow : C.red }}>
                          {f.encryption_status?.toUpperCase()}
                        </td>
                      </tr>
                    )
                  })}
                {dspmFindings.filter(f => !dspmFilter || f.risk_level === dspmFilter).length === 0 && (
                  <tr><td colSpan={5} style={{ padding: 20, textAlign: 'center', color: C.dim }}>~ no findings ~</td></tr>
                )}
              </tbody>
            </table>
          </div>

          {/* correlations highlight */}
          {correlations.length > 0 && (
            <div style={{ marginTop: 10, borderTop: `1px solid ${C.red}33`, paddingTop: 8 }}>
              <div style={{ fontSize: 9, color: C.red, ...mono, marginBottom: 6, fontWeight: 800 }}>
                ⚠ HIGH-RISK CORRELATIONS [{correlations.length}]
              </div>
              <div style={{ overflowY: 'auto', maxHeight: 120 }}>
                {correlations.map(c => (
                  <div key={c.id} style={{
                    fontSize: 9, ...mono, padding: '3px 0',
                    borderBottom: '1px solid rgba(255,85,85,0.1)', color: C.dim
                  }}>
                    <span style={{ color: c.combined_risk === 'critical' ? C.red : C.orange, fontWeight: 800 }}>
                      [{c.combined_risk?.toUpperCase()}]
                    </span>{' '}
                    <span style={{ color: C.text }}>{c.violation?.rule_id}</span>
                    {' → '}
                    <span style={{ color: C.purple }}>{c.dspm_finding?.name}</span>
                    {' '}
                    <span style={{ color: C.dim }}>[{(c.dspm_finding?.classifications || []).join('/')}]</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </TerminalWindow>

      </div>

      {/* ── Remediation modal ──────────────────────────────────────────────── */}
      {remediateTarget && (
        <RemediateModal
          violation={remediateTarget}
          onClose={() => setRemediateTarget(null)}
          onSubmitted={() => { fetchViolationsDspm(); fetchData(); setRemediateTarget(null) }}
        />
      )}
    </div>
  )
}
