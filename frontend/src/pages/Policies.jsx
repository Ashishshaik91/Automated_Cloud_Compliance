import React, { useState } from 'react'
import { CreditCard, HeartPulse, Globe, Shield, Lock, Search, AlertTriangle, PenTool } from 'lucide-react'
import TerminalWindow from '../components/TerminalWindow'
import api from '../api/client'

const INITIAL_FRAMEWORKS = [
  {
    id: 'pci_dss', name: 'PCI-DSS v4.0', icon: <CreditCard size={24} />,
    color: '#3b82f6', desc: 'Payment Card Industry Data Security Standard',
    checks: 7, active: true,
    policies: [
      { id: 'pci-s3-encryption-required', name: 'S3 Encryption Required', severity: 'critical', resource_type: 'S3 Bucket' },
      { id: 'pci-s3-no-public-access', name: 'S3 No Public Access', severity: 'critical', resource_type: 'S3 Bucket' },
      { id: 'pci-cloudtrail-enabled', name: 'CloudTrail Logging Enabled', severity: 'critical', resource_type: 'CloudTrail' },
      { id: 'pci-iam-mfa-required', name: 'IAM MFA Required', severity: 'critical', resource_type: 'IAM User' },
      { id: 'pci-rds-encryption-required', name: 'RDS Encryption Required', severity: 'critical', resource_type: 'RDS Instance' },
      { id: 'pci-rds-not-public', name: 'RDS Not Publicly Accessible', severity: 'critical', resource_type: 'RDS Instance' },
      { id: 'pci-cloudtrail-validation', name: 'CloudTrail Log Validation', severity: 'high', resource_type: 'CloudTrail' },
    ]
  },
  {
    id: 'hipaa', name: 'HIPAA Security Rule', icon: <HeartPulse size={24} />,
    color: '#8b5cf6', desc: 'Health Insurance Portability and Accountability Act',
    checks: 6, active: true,
    policies: [
      { id: 'hipaa-s3-encryption', name: 'PHI Storage Encryption', severity: 'critical', resource_type: 'S3 Bucket' },
      { id: 'hipaa-s3-no-public', name: 'PHI No Public Access', severity: 'critical', resource_type: 'S3 Bucket' },
      { id: 'hipaa-cloudtrail-enabled', name: 'Audit Logging Enabled', severity: 'critical', resource_type: 'CloudTrail' },
      { id: 'hipaa-iam-mfa', name: 'MFA for PHI Access', severity: 'high', resource_type: 'IAM User' },
      { id: 'hipaa-rds-encrypted', name: 'Database Encryption', severity: 'critical', resource_type: 'RDS Instance' },
      { id: 'hipaa-s3-versioning', name: 'S3 Versioning for Integrity', severity: 'medium', resource_type: 'S3 Bucket' },
    ]
  },
  {
    id: 'gdpr', name: 'GDPR', icon: <Globe size={24} />,
    color: '#10b981', desc: 'General Data Protection Regulation',
    checks: 5, active: true,
    policies: [
      { id: 'gdpr-s3-encryption', name: 'Personal Data Encryption', severity: 'high', resource_type: 'S3 Bucket' },
      { id: 'gdpr-s3-no-public', name: 'No Public Access to Personal Data', severity: 'high', resource_type: 'S3 Bucket' },
      { id: 'gdpr-cloudtrail-audit', name: 'Audit Logging (Art. 30)', severity: 'high', resource_type: 'CloudTrail' },
      { id: 'gdpr-s3-versioning', name: 'Data Lifecycle Management', severity: 'medium', resource_type: 'S3 Bucket' },
      { id: 'gdpr-rds-encryption', name: 'Database Encryption', severity: 'high', resource_type: 'RDS Instance' },
    ]
  },
  {
    id: 'soc2', name: 'SOC 2 Type II', icon: <Shield size={24} />,
    color: '#f59e0b', desc: 'System and Organization Controls',
    checks: 6, active: true,
    policies: [
      { id: 'soc2-iam-mfa', name: 'MFA for All Users (CC6.1)', severity: 'high', resource_type: 'IAM User' },
      { id: 'soc2-s3-no-public', name: 'S3 No Public Access (CC6.7)', severity: 'high', resource_type: 'S3 Bucket' },
      { id: 'soc2-cloudtrail-monitoring', name: 'System Monitoring (CC7.2)', severity: 'high', resource_type: 'CloudTrail' },
      { id: 'soc2-rds-multi-az', name: 'High Availability (A1.2)', severity: 'medium', resource_type: 'RDS Instance' },
      { id: 'soc2-rds-not-public', name: 'No External DB Access (CC6.6)', severity: 'high', resource_type: 'RDS Instance' },
      { id: 'soc2-s3-encryption', name: 'Data Encryption (CC6.1)', severity: 'high', resource_type: 'S3 Bucket' },
    ]
  },
  {
    id: 'nist', name: 'NIST SP 800-53', icon: <Lock size={24} />,
    color: '#0ea5e9', desc: 'National Institute of Standards and Technology',
    checks: 5, active: true,
    policies: [
      { id: 'nist-audit-logging', name: 'Audit Logging Enabled (AU-2)', severity: 'high', resource_type: 'CloudTrail' },
      { id: 'nist-crypto-fips', name: 'FIPS Validated Crypto (SC-13)', severity: 'critical', resource_type: 'S3 Bucket' },
      { id: 'nist-iam-mfa', name: 'Authenticator Management (IA-5)', severity: 'critical', resource_type: 'IAM User' },
      { id: 'nist-least-privilege', name: 'Least Privilege (AC-6)', severity: 'high', resource_type: 'IAM Policy' },
      { id: 'nist-data-at-rest', name: 'Protection of Info at Rest (SC-28)', severity: 'critical', resource_type: 'RDS Instance' },
    ]
  },
  {
    id: 'cis', name: 'CIS Benchmarks', icon: <Search size={24} />,
    color: '#14b8a6', desc: 'Center for Internet Security Settings',
    checks: 4, active: true,
    policies: [
      { id: 'cis-root-mfa', name: 'Avoid Root usage & ensure MFA', severity: 'critical', resource_type: 'IAM Root' },
      { id: 'cis-iam-password', name: 'Strong Password Policy', severity: 'high', resource_type: 'IAM Policy' },
      { id: 'cis-sg-ssh-open', name: 'No Open SSH to 0.0.0.0/0', severity: 'critical', resource_type: 'Security Group' },
      { id: 'cis-storage-encryption', name: 'Storage Account Encrypted', severity: 'high', resource_type: 'Storage Blob' },
    ]
  },
  {
    id: 'owasp', name: 'OWASP Top 10', icon: <AlertTriangle size={24} />,
    color: '#ef4444', desc: 'Open Web Application Security Project',
    checks: 4, active: true,
    policies: [
      { id: 'owasp-waf-enabled', name: 'WAF Enabled for APIs (A1:2021)', severity: 'critical', resource_type: 'API Gateway' },
      { id: 'owasp-tls-version', name: 'TLS 1.2+ Only (A2:2021)', severity: 'high', resource_type: 'Load Balancer' },
      { id: 'owasp-cors-strict', name: 'Restrictive CORS (A5:2021)', severity: 'medium', resource_type: 'API Gateway' },
      { id: 'owasp-log-injection', name: 'Log Integrity Monitoring (A9:2021)', severity: 'high', resource_type: 'CloudTrail' },
    ]
  },
  {
    id: 'custom', name: 'User Custom', icon: <PenTool size={24} />,
    color: '#ff79c6', desc: 'Custom User-Defined Policies',
    checks: 0, active: true,
    policies: []
  }
]

export default function Policies({ role = 'viewer' }) {
  const [frameworks, setFrameworks] = useState(INITIAL_FRAMEWORKS)
  const [selected, setSelected] = useState(frameworks[0])
  const [showBuilder, setShowBuilder] = useState(false)
  const [customForm, setCustomForm] = useState({ name: '', resource_type: '', severity: 'high', field: '', operator: 'is_true' })
  const [building, setBuilding] = useState(false)
  const [policySearch,  setPolicySearch]  = useState('')
  const [policySevFilter, setPolicySevFilter] = useState(null)
  const canCreate = ['admin', 'auditor'].includes(role)

  // filtered view of the selected framework's policies
  const filteredPolicies = selected.policies.filter(p => {
    const matchSev   = !policySevFilter || p.severity === policySevFilter
    const matchText  = !policySearch    ||
      p.name?.toLowerCase().includes(policySearch.toLowerCase()) ||
      p.id?.toLowerCase().includes(policySearch.toLowerCase())   ||
      p.resource_type?.toLowerCase().includes(policySearch.toLowerCase())
    return matchSev && matchText
  })

  const handleCreatePolicy = async (e) => {
    e.preventDefault()
    setBuilding(true)
    try {
      const res = await api.post('/compliance/custom-policy', customForm)
      const newPol = res.data.policy
      
      const updated = frameworks.map(fw => {
        if (fw.id === 'custom') {
          return { ...fw, checks: fw.checks + 1, policies: [...fw.policies, newPol] }
        }
        return fw
      })
      setFrameworks(updated)
      setSelected(updated.find(f => f.id === selected.id))
      setShowBuilder(false)
      setCustomForm({ name: '', resource_type: '', severity: 'high', field: '', operator: 'is_true' })
      alert('Policy successfully injected into OPA engine!')
    } catch(err) {
      alert(err.response?.data?.detail || 'Failed to build policy')
    }
    setBuilding(false)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, fontFamily: 'var(--font-main)', paddingBottom: 40 }}>
      {/* HEADER DIV */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', borderBottom: '1px solid var(--color-border)', paddingBottom: 16 }}>
        <div>
          <div style={{ fontSize: 12, color: 'var(--color-primary)', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>$ ls /etc/compliance/policies</div>
          <div style={{ fontSize: 20, fontWeight: 900, fontFamily: 'var(--font-mono)' }}>policy-library <span style={{ color: 'var(--color-text-dim)', fontWeight: 400 }}>--framework-drilldown</span></div>
        </div>
        {canCreate && (
          <button 
            className="btn-status" 
            onClick={() => setShowBuilder(!showBuilder)} 
            style={{ 
              background: 'none',
              border: '1px solid var(--color-primary)',
              color: 'var(--color-primary)',
              padding: '6px 16px',
              fontSize: 11,
              fontFamily: 'var(--font-mono)',
              fontWeight: 800,
              cursor: 'pointer',
              borderRadius: 2
            }}
          >
            {showBuilder ? '> CANCEL_BUILD' : '> BUILD_CUSTOM_POLICY'}
          </button>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 24 }}>
        {/* Framework list */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {frameworks.map(f => (
            <div
              key={f.id}
              onClick={() => {
                setSelected(f)
                setShowBuilder(false)
                setPolicySearch('')
                setPolicySevFilter(null)
              }}
              style={{
                cursor: 'pointer',
                padding: '12px 16px',
                border: `1px solid ${selected.id === f.id && !showBuilder ? 'var(--color-primary)' : 'var(--color-border)'}`,
                background: selected.id === f.id && !showBuilder ? 'rgba(189, 147, 249, 0.1)' : 'none',
                fontFamily: 'var(--font-mono)',
                transition: 'all 0.2s',
                position: 'relative',
                overflow: 'hidden'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span style={{ color: selected.id === f.id && !showBuilder ? 'var(--color-primary)' : 'var(--color-text-dim)' }}>
                  {React.cloneElement(f.icon, { size: 18 })}
                </span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 800, fontSize: 12, color: selected.id === f.id && !showBuilder ? 'var(--color-primary)' : 'var(--color-text)' }}>
                    {f.name?.toUpperCase()}
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--color-text-dim)' }}>
                    {f.checks} POLICIES LOADED
                  </div>
                </div>
                {selected.id === f.id && !showBuilder && <div style={{ fontSize: 10, color: 'var(--color-primary)' }}>{'>'}</div>}
              </div>
            </div>
          ))}
          
          <div style={{ marginTop: 'auto', padding: 16, border: '1px solid var(--color-border)', background: 'rgba(0,0,0,0.2)' }}>
            <div style={{ fontSize: 10, color: 'var(--color-info)', fontFamily: 'var(--font-mono)', marginBottom: 8 }}>[ ENGINE_STATUS ]</div>
            <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)' }}>
              <span style={{ color: 'var(--color-success)' }}>●</span> OPA_READY: TRUE
              <br/>
              <span style={{ color: 'var(--color-success)' }}>●</span> REGO_LOADED: 100%
            </div>
          </div>
        </div>

        {/* Dynamic Canvas Area */}
        {showBuilder ? (
          <TerminalWindow title="custom_policy_compiler.exe">
             <form onSubmit={handleCreatePolicy} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
               <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div>
                  <label style={{ display: 'block', fontSize: 10, color: 'var(--color-primary)', marginBottom: 8, fontFamily: 'var(--font-mono)' }}>{'>>'} POLICY_NAME (e.g. S3 Public Access Denied)</label>
                  <input required value={customForm.name} onChange={e => setCustomForm({...customForm, name: e.target.value})} style={{ width: '100%', padding: 8, background: 'rgba(255,255,255,0.05)', border: '1px solid var(--color-border)', color: 'white', outline: 'none', fontFamily: 'var(--font-mono)', fontSize: 12 }} />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: 10, color: 'var(--color-primary)', marginBottom: 8, fontFamily: 'var(--font-mono)' }}>{'>>'} TARGET_RESOURCE (e.g. S3 Bucket)</label>
                  <input required value={customForm.resource_type} onChange={e => setCustomForm({...customForm, resource_type: e.target.value})} style={{ width: '100%', padding: 8, background: 'rgba(255,255,255,0.05)', border: '1px solid var(--color-border)', color: 'white', outline: 'none', fontFamily: 'var(--font-mono)', fontSize: 12 }} />
                </div>
               </div>

               <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
                <div>
                  <label style={{ display: 'block', fontSize: 10, color: 'var(--color-primary)', marginBottom: 8, fontFamily: 'var(--font-mono)' }}>{'>>'} FIELD_KEY (e.g. is_public)</label>
                  <input required value={customForm.field} onChange={e => setCustomForm({...customForm, field: e.target.value})} style={{ width: '100%', padding: 8, background: 'rgba(255,255,255,0.05)', border: '1px solid var(--color-border)', color: 'white', outline: 'none', fontFamily: 'var(--font-mono)', fontSize: 12 }} />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: 10, color: 'var(--color-primary)', marginBottom: 8, fontFamily: 'var(--font-mono)' }}>{'>>'} EVAL_OPERATOR</label>
                  <select value={customForm.operator} onChange={e => setCustomForm({...customForm, operator: e.target.value})} style={{ width: '100%', padding: 8, background: 'rgba(255,255,255,0.05)', border: '1px solid var(--color-border)', color: 'white', outline: 'none', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                    <option value="is_true" style={{ background: '#1a1b26' }}>MUST BE TRUE</option>
                    <option value="is_false" style={{ background: '#1a1b26' }}>MUST BE FALSE</option>
                    <option value="equals" style={{ background: '#1a1b26' }}>EQUALS</option>
                    <option value="not_equals" style={{ background: '#1a1b26' }}>NOT EQUALS</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: 10, color: 'var(--color-primary)', marginBottom: 8, fontFamily: 'var(--font-mono)' }}>{'>>'} RISK_SEVERITY</label>
                  <select value={customForm.severity} onChange={e => setCustomForm({...customForm, severity: e.target.value})} style={{ width: '100%', padding: 8, background: 'rgba(255,255,255,0.05)', border: '1px solid var(--color-border)', color: 'white', outline: 'none', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                    <option value="low" style={{ background: '#1a1b26' }}>LOW</option>
                    <option value="medium" style={{ background: '#1a1b26' }}>MEDIUM</option>
                    <option value="high" style={{ background: '#1a1b26' }}>HIGH</option>
                    <option value="critical" style={{ background: '#1a1b26' }}>CRITICAL</option>
                  </select>
                </div>
               </div>

               <button type="submit" disabled={building} style={{ background: 'var(--color-primary)', color: '#000', border: 'none', padding: '12px', fontWeight: 900, fontSize: 12, fontFamily: 'var(--font-mono)', cursor: 'pointer', borderRadius: 2, marginTop: 16 }}>
                 {building ? '>> DEPLOYING_TO_OPA...' : '>> INJECT_POLICY'}
               </button>
             </form>
          </TerminalWindow>
        ) : (
          <TerminalWindow title={`${selected.id}_v2_manifest.yaml`}>
            {/* ── Filter bar ── */}
            {!showBuilder && (
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 14, flexWrap: 'wrap' }}>
                {/* text search */}
                <input
                  type="text"
                  placeholder="Search policies..."
                  value={policySearch}
                  onChange={e => setPolicySearch(e.target.value)}
                  style={{
                    flex: 1, minWidth: 140, padding: '5px 10px',
                    background: 'rgba(255,255,255,0.05)',
                    border: '1px solid var(--color-border)',
                    color: 'var(--color-text)', fontSize: 11,
                    fontFamily: 'var(--font-mono)', outline: 'none'
                  }}
                />
                {/* severity filter pills */}
                {['critical','high','medium','low'].map(sev => {
                  const clr = sev === 'critical' ? 'var(--color-danger)'
                            : sev === 'high'     ? 'var(--color-warning)'
                            : sev === 'medium'   ? 'var(--color-info)'
                            : 'var(--color-text-dim)'
                  const active = policySevFilter === sev
                  const cnt = selected.policies.filter(p => p.severity === sev).length
                  return (
                    <button key={sev} onClick={() => setPolicySevFilter(prev => prev === sev ? null : sev)}
                      style={{
                        padding: '3px 10px', fontSize: 9, fontFamily: 'var(--font-mono)',
                        fontWeight: 800, cursor: 'pointer', border: `1px solid ${clr}`,
                        background: active ? `${clr}22` : 'none',
                        color: active ? clr : 'var(--color-text-dim)',
                        borderRadius: 2, transition: 'all 0.15s'
                      }}
                    >
                      {sev.toUpperCase()} ({cnt})
                    </button>
                  )
                })}
                <div style={{ fontSize: 9, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', marginLeft: 'auto' }}>
                  {filteredPolicies.length}/{selected.policies.length} SHOWN
                </div>
              </div>
            )}

            <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 24, borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: 16 }}>
              <span style={{ color: 'var(--color-primary)', opacity: 0.8 }}>{React.cloneElement(selected.icon, { size: 32 })}</span>
              <div style={{ flex: 1 }}>
                <h2 style={{ fontSize: 18, fontWeight: 900, fontFamily: 'var(--font-mono)', margin: 0 }}>{selected.name}</h2>
                <div style={{ color: 'var(--color-text-dim)', fontSize: 11, fontFamily: 'var(--font-mono)', marginTop: 4 }}>
                  {(selected.desc || 'NO_DESCRIPTION').toUpperCase()}
                </div>
              </div>
              <div style={{ 
                border: '1px solid var(--color-success)', 
                color: 'var(--color-success)', 
                padding: '2px 8px', 
                fontSize: 10, 
                fontWeight: 800, 
                fontFamily: 'var(--font-mono)' 
              }}>
                [ STATUS: ACTIVE ]
              </div>
            </div>

            <div style={{ overflowX: 'auto', maxHeight: '500px' }}>
              <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                <thead>
                  <tr style={{ textAlign: 'left', color: 'var(--color-info)', borderBottom: '1px solid var(--color-border)' }}>
                    <th style={{ padding: '10px 4px' }}>POLICY_ID</th>
                    <th style={{ padding: '10px 4px' }}>DEFINITION</th>
                    <th style={{ padding: '10px 4px' }}>TARGET_RESOURCE</th>
                    <th style={{ padding: '10px 4px' }}>SEVERITY</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredPolicies.length === 0 ? (
                    <tr><td colSpan="4" style={{textAlign:'center', padding: '40px', color: 'var(--color-text-dim)'}}>[ NO_RECORDS ]</td></tr>
                  ) : filteredPolicies.map(p => (
                    <tr key={p.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                      <td style={{ padding: '10px 4px', color: 'var(--color-text-dim)' }}>{p.id}</td>
                      <td style={{ padding: '10px 4px', fontWeight: 700 }}>{p.name?.toUpperCase()}</td>
                      <td style={{ padding: '10px 4px', color: 'var(--color-accent)' }}>{p.resource_type}</td>
                      <td style={{ padding: '10px 4px' }}>
                        <span style={{ 
                          color: p.severity === 'critical' ? 'var(--color-danger)' : p.severity === 'high' ? 'var(--color-warning)' : 'var(--color-info)',
                          fontWeight: 900
                        }}>
                          [{p.severity?.toUpperCase()}]
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            
            <div style={{ marginTop: 24, padding: 12, background: 'rgba(189, 147, 249, 0.05)', border: '1px dashed var(--color-primary)', fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--color-text-dim)' }}>
              [ NOTICE ] THESE POLICIES ARE IMMUTABLE AND EVALUATED ON EVERY SCAN TRIGGER VIA OPA REGO DEFINITIONS.
            </div>
          </TerminalWindow>
        )}
      </div>
    </div>
  )
}
