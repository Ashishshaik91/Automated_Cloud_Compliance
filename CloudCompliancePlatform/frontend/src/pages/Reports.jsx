import React, { useState, useEffect } from 'react'
import api from '../api/client'

export default function Reports() {
  const [generating, setGenerating] = useState(null)
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchScans = async () => {
      try {
        const res = await api.get('/scans')
        setScans(res.data)
      } catch (err) {
        console.error('Failed to load scans for reports', err)
      } finally {
        setLoading(false)
      }
    }
    fetchScans()
  }, [])

  const generateReport = async (scan) => {
    setGenerating(scan.id)
    try {
      // 1. Generate the report via API
      const res = await api.post('/reports/generate', { scan_id: scan.id, format: 'html' })
      const downloadUrl = res.data.download_url
      
      // 2. Download the actual file using axios to include Authorization header
      const reportRes = await api.get(`${downloadUrl}?scan_id=${scan.id}`, { responseType: 'blob' })
      
      // 3. Trigger browser download
      const url = window.URL.createObjectURL(new Blob([reportRes.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `compliance_report_${scan.id}.html`)
      document.body.appendChild(link)
      link.click()
      link.parentNode.removeChild(link)
      
    } catch (err) {
      console.error('Failed to generate report', err)
      alert('Failed to generate or download report.')
    } finally {
      setGenerating(null)
    }
  }

  const scoreColor = (s) => s >= 80 ? 'var(--color-success)' : s >= 60 ? 'var(--color-warning)' : 'var(--color-danger)'

  return (
    <div className="main-content">
      <header className="top-bar">
        <span style={{ fontWeight: 600, fontSize: 16 }}>Audit Reports</span>
        <span style={{ fontSize: 13, color: 'var(--color-text-muted)' }}>Generate audit-ready compliance reports</span>
      </header>

      <div className="page-content fade-in">
        <div className="page-header">
          <h1 className="page-title">Compliance Reports</h1>
          <p className="page-subtitle">Generate and download audit-ready reports for all frameworks and scans.</p>
        </div>

        {loading ? (
           <div className="loading-center">
             <div className="spinner"></div>
             Loading scan history...
           </div>
        ) : scans.length === 0 ? (
          <div className="card" style={{ textAlign: 'center', padding: '60px', color: 'var(--color-text-muted)' }}>
            No scans available yet. Trigger a scan from the Dashboard to generate reports.
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 20 }}>
            {scans.map(scan => (
              <div className="card" key={scan.id} style={{ position: 'relative' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
                  <div>
                    <span className="badge medium" style={{ marginBottom: 8, textTransform: 'uppercase' }}>{scan.framework}</span>
                    <div style={{ fontSize: 13, color: 'var(--color-text-muted)', marginTop: 6 }}>
                      Scan #{scan.id} • {new Date(scan.started_at).toLocaleString()}
                    </div>
                  </div>
                  <span style={{ fontSize: 28, fontWeight: 800, color: scoreColor(scan.compliance_score) }}>
                    {scan.compliance_score}%
                  </span>
                </div>

                <div style={{ display: 'flex', gap: 16, marginBottom: 20 }}>
                  <div style={{ textAlign: 'center', flex: 1, padding: '10px', background: 'rgba(16,185,129,0.08)', borderRadius: 8 }}>
                    <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--color-success)' }}>{scan.passed_checks}</div>
                    <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>Passed</div>
                  </div>
                  <div style={{ textAlign: 'center', flex: 1, padding: '10px', background: 'rgba(239,68,68,0.08)', borderRadius: 8 }}>
                    <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--color-danger)' }}>{scan.failed_checks}</div>
                    <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>Failed</div>
                  </div>
                </div>

                <button
                  className="btn btn-primary btn-full"
                  onClick={() => generateReport(scan)}
                  disabled={generating === scan.id}
                >
                  {generating === scan.id ? '⏳ Generating...' : '📄 Generate Report'}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
