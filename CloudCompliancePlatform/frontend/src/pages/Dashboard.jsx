import React, { useState, useEffect } from 'react'
import { RadialBarChart, RadialBar, PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts'
import api from '../api/client'

const FRAMEWORKS = ['pci_dss', 'hipaa', 'gdpr', 'soc2']
const FRAMEWORK_DISPLAY_NAMES = {
  pci_dss: 'PCI-DSS',
  hipaa: 'HIPAA',
  gdpr: 'GDPR',
  soc2: 'SOC 2'
}

const SEVERITY_COLORS = { critical: '#ef4444', high: '#f59e0b', medium: '#06b6d4', low: '#6b7280' }

const ScoreBar = ({ name, score, color }) => {
  const barClass = score >= 80 ? 'green' : score >= 60 ? 'yellow' : 'red'
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
        <span style={{ fontSize: 13, fontWeight: 500 }}>{name}</span>
        <span style={{ fontSize: 13, fontWeight: 700, color: score >= 80 ? 'var(--color-success)' : score >= 60 ? 'var(--color-warning)' : 'var(--color-danger)' }}>
          {score.toFixed(1)}%
        </span>
      </div>
      <div className="progress-bar-container">
        <div className={`progress-bar ${barClass}`} style={{ width: `${Math.max(0, Math.min(100, score))}%` }} />
      </div>
    </div>
  )
}

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload?.length) {
    return (
      <div style={{ background: 'var(--color-surface-2)', border: '1px solid var(--color-border)', borderRadius: 8, padding: '8px 12px', fontSize: 13 }}>
        <p style={{ color: 'var(--color-text-muted)', marginBottom: 4 }}>{label}</p>
        <p style={{ color: 'var(--color-primary)', fontWeight: 700 }}>{payload[0].value}%</p>
      </div>
    )
  }
  return null
}

export default function Dashboard() {
  const [activeFramework, setActiveFramework] = useState('All')
  const [loading, setLoading] = useState(true)
  const [scanLoading, setScanLoading] = useState(false)
  
  const [summary, setSummary] = useState({
    total_accounts: 0,
    overall_score: 0,
    critical_failures: 0,
    high_failures: 0,
    last_scan_at: null,
  })
  
  const [checks, setChecks] = useState([])
  const [scores, setScores] = useState([])
  const [trend, setTrend] = useState([])
  const [severityDist, setSeverityDist] = useState([])

  const fetchData = async () => {
    try {
      setLoading(true)
      
      const [sumRes, checksRes, scansRes] = await Promise.all([
        api.get('/compliance/summary'),
        api.get('/compliance/checks?limit=100'),
        api.get('/scans')
      ])
      
      setSummary(sumRes.data)
      setChecks(checksRes.data)
      
      // Calculate severity distribution
      const dist = { Critical: 0, High: 0, Medium: 0, Low: 0 }
      checksRes.data.forEach(c => {
        if (c.status === 'fail') {
          const sev = c.severity.charAt(0).toUpperCase() + c.severity.slice(1)
          if (dist[sev] !== undefined) dist[sev]++
        }
      })
      setSeverityDist([
        { name: 'Critical', value: dist.Critical, color: '#ef4444' },
        { name: 'High', value: dist.High, color: '#f59e0b' },
        { name: 'Medium', value: dist.Medium, color: '#06b6d4' },
        { name: 'Low', value: dist.Low, color: '#6b7280' },
      ])

      // Process Scans to compute framework scores and trends
      const scans = scansRes.data || []
      
      // Latest score per framework
      const fwScores = {}
      scans.forEach(s => {
        if (!fwScores[s.framework] || new Date(s.started_at) > new Date(fwScores[s.framework].started_at)) {
          fwScores[s.framework] = s
        }
      })
      
      const sc = FRAMEWORKS.map(fw => ({
        name: FRAMEWORK_DISPLAY_NAMES[fw] || fw,
        score: fwScores[fw] ? fwScores[fw].compliance_score : 100
      }))
      setScores(sc)
      
      // Compute Trend (grouping dates)
      const dateMap = {}
      scans.forEach(s => {
        const d = new Date(s.started_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
        if (!dateMap[d]) dateMap[d] = []
        dateMap[d].push(s.compliance_score)
      })
      
      const trendData = Object.keys(dateMap).map(d => {
        const avg = dateMap[d].reduce((a,b)=>a+b, 0) / dateMap[d].length
        return { date: d, score: Number(avg.toFixed(1)) }
      }).sort((a,b) => new Date(a.date) - new Date(b.date)).slice(-10) // last 10 scan dates
      
      setTrend(trendData.length > 0 ? trendData : [{date: 'No Data', score: 100}])
      
    } catch (err) {
      console.error("Failed to load dashboard data", err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const filteredChecks = activeFramework === 'All'
    ? checks
    : checks.filter(c => c.framework === activeFramework)

  const triggerScan = async () => {
    setScanLoading(true)
    try {
      // Assuming account id 1 exists
      await api.post('/scans/trigger', { account_id: 1, framework: 'all' })
      alert('✅ Scan triggered! Results will update shortly.')
      setTimeout(fetchData, 3000) // refresh data
    } catch (e) {
      alert('❌ Failed to trigger scan. Does account_id=1 exist?')
    }
    setScanLoading(false)
  }

  return (
    <div className="main-content">
      <header className="top-bar">
        <div>
          <span style={{ fontWeight: 600, fontSize: 16 }}>Compliance Dashboard</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--color-success)', boxShadow: '0 0 8px var(--color-success)' }} />
          <span style={{ fontSize: 13, color: 'var(--color-text-muted)' }}>Live monitoring active</span>
          <button
            className="btn btn-primary"
            onClick={triggerScan}
            disabled={scanLoading}
            style={{ fontSize: 13, padding: '7px 14px' }}
          >
            {scanLoading ? '⏳ Scanning...' : '⚡ Trigger Scan'}
          </button>
        </div>
      </header>

      <div className="page-content fade-in">
        {loading ? (
           <div className="loading-center">
             <div className="spinner"></div>
             Checking Compliance Posture...
           </div>
        ) : (
          <>
            <div className="stats-grid">
              <div className="stat-card blue">
                <div className="stat-icon blue">☁️</div>
                <div className="stat-value" style={{ color: 'var(--color-primary)' }}>{summary.total_accounts}</div>
                <div className="stat-label">Cloud Accounts</div>
                <div className="stat-change up">↑ Active connections</div>
              </div>
              <div className="stat-card green">
                <div className="stat-icon green">🎯</div>
                <div className="stat-value" style={{ color: 'var(--color-success)' }}>{summary.overall_score}%</div>
                <div className="stat-label">Overall Compliance</div>
                <div className="stat-change up">Latest combined score</div>
              </div>
              <div className="stat-card red">
                <div className="stat-icon red">🚨</div>
                <div className="stat-value" style={{ color: 'var(--color-danger)' }}>{summary.critical_failures}</div>
                <div className="stat-label">Critical Failures</div>
                <div className="stat-change down">↓ Requires immediate action</div>
              </div>
              <div className="stat-card yellow">
                <div className="stat-icon yellow">⚠️</div>
                <div className="stat-value" style={{ color: 'var(--color-warning)' }}>{summary.high_failures}</div>
                <div className="stat-label">High Severity Issues</div>
                <div className="stat-change">Review within 7 days</div>
              </div>
            </div>

            <div className="charts-grid">
              <div className="card">
                <div className="chart-title">Compliance Score Trend</div>
                <div className="chart-subtitle">Historical scan average</div>
                <ResponsiveContainer width="100%" height={180}>
                  <LineChart data={trend}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                    <XAxis dataKey="date" tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis domain={[0, 100]} tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip content={<CustomTooltip />} />
                    <Line type="monotone" dataKey="score" stroke="#3b82f6" strokeWidth={2.5}
                      dot={{ fill: '#3b82f6', strokeWidth: 0, r: 4 }}
                      activeDot={{ r: 6, fill: '#60a5fa' }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              <div className="card">
                <div className="chart-title">Issue Severity Distribution</div>
                <div className="chart-subtitle">Current open violations</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
                  <PieChart width={160} height={160}>
                    <Pie data={severityDist} cx={75} cy={75} innerRadius={45} outerRadius={70}
                      paddingAngle={3} dataKey="value">
                      {severityDist.map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                      ))}
                    </Pie>
                  </PieChart>
                  <div>
                    {severityDist.map((s) => (
                      <div key={s.name} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                        <div style={{ width: 10, height: 10, borderRadius: 2, background: s.color, flexShrink: 0 }} />
                        <span style={{ fontSize: 13, color: 'var(--color-text-muted)' }}>{s.name}</span>
                        <span style={{ fontSize: 13, fontWeight: 700, marginLeft: 'auto' }}>{s.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(280px, 320px) 1fr', gap: 20 }}>
              <div className="card">
                <div className="chart-title" style={{ marginBottom: 4 }}>Framework Scores</div>
                <div className="chart-subtitle">Latest scan results by standard</div>
                {scores.map(s => <ScoreBar key={s.name} {...s} />)}
              </div>

              <div className="card" style={{ overflow: 'hidden' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                  <div>
                    <div className="chart-title">Compliance Checks</div>
                    <div className="chart-subtitle">Recent policy evaluations</div>
                  </div>
                </div>

                <div className="framework-pills">
                  {['All', ...FRAMEWORKS].map(f => {
                    const disp = f === 'All' ? 'All' : FRAMEWORK_DISPLAY_NAMES[f] || f;
                    return (
                      <button
                        key={f}
                        className={`framework-pill ${activeFramework === f ? 'active' : ''}`}
                        onClick={() => setActiveFramework(f)}
                      >
                        {disp}
                      </button>
                    )
                  })}
                </div>

                <div style={{ overflowX: 'auto', maxHeight: '400px', overflowY: 'auto' }}>
                  <table className="data-table">
                    <thead style={{ position: 'sticky', top: 0, background: 'var(--color-surface)' }}>
                      <tr>
                        <th>Policy</th>
                        <th>Framework</th>
                        <th>Resource</th>
                        <th>Severity</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredChecks.length === 0 ? (
                        <tr><td colSpan="5" style={{textAlign:'center', padding: '30px', color: 'var(--color-text-muted)'}}>No checks recorded. Run a scan.</td></tr>
                      ) : filteredChecks.map(c => (
                        <tr key={c.id}>
                          <td style={{ fontWeight: 500, maxWidth: 240 }}>{c.policy_name}</td>
                          <td>
                            <span className="badge medium">{FRAMEWORK_DISPLAY_NAMES[c.framework] || c.framework}</span>
                          </td>
                          <td style={{ color: 'var(--color-text-muted)', fontFamily: 'monospace', fontSize: 13 }}>
                            {c.resource_id}
                          </td>
                          <td><span className={`badge ${c.severity}`}>{c.severity}</span></td>
                          <td>
                            <span className={`badge ${c.status === 'pass' ? 'pass' : 'fail'}`}>
                              {c.status === 'pass' ? '✓ Pass' : '✗ Fail'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
