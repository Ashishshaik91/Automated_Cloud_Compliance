import React, { useState, useEffect } from 'react'
import api from '../api/client'
import TerminalWindow from '../components/TerminalWindow'

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

  const generateReport = async (scan, format = 'html') => {
    setGenerating(`${scan.id}-${format}`)
    try {
      // 1. Generate the report via API
      const res = await api.post('/reports/generate', { scan_id: scan.id, format })
      const downloadUrl = res.data.download_url
      
      // 2. Download the actual file using axios to include Authorization header
      // downloadUrl already contains ?fmt={format}, axios merges params
      const reportRes = await api.get(downloadUrl, { 
        params: { scan_id: scan.id },
        responseType: 'blob' 
      })
      
      // 3. Trigger browser download
      const url = window.URL.createObjectURL(new Blob([reportRes.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `compliance_report_${scan.id}.${format}`)
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

  if (loading) return <div className="loading-center" style={{ fontFamily: 'var(--font-mono)' }}>./loading_reports --status history</div>

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, fontFamily: 'var(--font-main)' }}>
      <div style={{ borderBottom: '1px solid var(--color-border)', paddingBottom: 16 }}>
        <div style={{ fontSize: 12, color: 'var(--color-primary)', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>$ ls /var/log/reports</div>
        <div style={{ fontSize: 20, fontWeight: 900, fontFamily: 'var(--font-mono)' }}>compliance-reports <span style={{ color: 'var(--color-text-dim)', fontWeight: 400 }}>--archives</span></div>
      </div>

      {scans.length === 0 ? (
        <TerminalWindow title="empty_directory.log">
          <div style={{ textAlign: 'center', padding: '40px', color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)' }}>
            [ NOTICE ] No scan records found in the local database.
          </div>
        </TerminalWindow>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 24 }}>
          {scans.map(scan => (
            <TerminalWindow key={scan.id} title={`report_scan_${scan.id.toString().padStart(3, '0')}.md`}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
                <div style={{ fontFamily: 'var(--font-mono)' }}>
                   <div style={{ color: 'var(--color-primary)', fontWeight: 800, fontSize: 13 }}>{scan.framework?.toUpperCase()}</div>
                  <div style={{ fontSize: 10, color: 'var(--color-text-dim)', marginTop: 4 }}>
                    TIMESTAMP: {new Date(scan.started_at).toISOString().replace('T', ' ').split('.')[0]}
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: 24, fontWeight: 900, color: scoreColor(scan.compliance_score), fontFamily: 'var(--font-mono)' }}>
                    {(scan.compliance_score || 0).toFixed(1)}%
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)' }}>COMPLIANCE_SCORE</div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: 12, marginBottom: 24, fontFamily: 'var(--font-mono)' }}>
                <div style={{ flex: 1, padding: '12px', border: '1px solid rgba(80, 250, 123, 0.2)', background: 'rgba(80, 250, 123, 0.05)' }}>
                  <div style={{ fontSize: 18, fontWeight: 900, color: 'var(--color-success)' }}>{scan.passed_checks}</div>
                  <div style={{ fontSize: 9, color: 'var(--color-success)', opacity: 0.8 }}>PASSED_CHECKS</div>
                </div>
                <div style={{ flex: 1, padding: '12px', border: '1px solid rgba(255, 85, 85, 0.2)', background: 'rgba(255, 85, 85, 0.05)' }}>
                  <div style={{ fontSize: 18, fontWeight: 900, color: 'var(--color-danger)' }}>{scan.failed_checks}</div>
                  <div style={{ fontSize: 9, color: 'var(--color-danger)', opacity: 0.8 }}>FAILED_CHECKS</div>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
                {['pdf', 'csv', 'html'].map(fmt => (
                  <button
                    key={fmt}
                    onClick={() => generateReport(scan, fmt)}
                    disabled={generating !== null}
                    style={{
                      width: '100%',
                      background: generating === `${scan.id}-${fmt}` ? 'rgba(255,255,255,0.1)' : 'none',
                      border: '1px solid var(--color-primary)',
                      color: 'var(--color-primary)',
                      padding: '10px',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 11,
                      fontWeight: 800,
                      cursor: 'pointer',
                      borderRadius: 2,
                      transition: 'all 0.2s',
                      opacity: generating !== null && generating !== `${scan.id}-${fmt}` ? 0.5 : 1
                    }}
                  >
                    {generating === `${scan.id}-${fmt}` ? '> ...' : `> ${fmt.toUpperCase()}`}
                  </button>
                ))}
              </div>
            </TerminalWindow>
          ))}
        </div>
      )}
    </div>
  )
}
