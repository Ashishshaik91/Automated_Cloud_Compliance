import React, { useState } from 'react'

const FRAMEWORKS_DETAIL = [
  {
    id: 'pci_dss', name: 'PCI-DSS v4.0', icon: '💳',
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
    id: 'hipaa', name: 'HIPAA Security Rule', icon: '🏥',
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
    id: 'gdpr', name: 'GDPR', icon: '🇪🇺',
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
    id: 'soc2', name: 'SOC 2 Type II', icon: '🔐',
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
]

export default function Policies() {
  const [selected, setSelected] = useState(FRAMEWORKS_DETAIL[0])

  return (
    <div className="main-content">
      <header className="top-bar">
        <span style={{ fontWeight: 600, fontSize: 16 }}>Policy Library</span>
        <span style={{ fontSize: 13, color: 'var(--color-text-muted)' }}>
          {FRAMEWORKS_DETAIL.reduce((a, f) => a + f.checks, 0)} active policies across 4 frameworks
        </span>
      </header>

      <div className="page-content fade-in">
        <div className="page-header">
          <h1 className="page-title">Compliance Policies</h1>
          <p className="page-subtitle">All compliance-as-code policies loaded from YAML and evaluated via Open Policy Agent (OPA).</p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 20 }}>
          {/* Framework list */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {FRAMEWORKS_DETAIL.map(f => (
              <div
                key={f.id}
                className={`card ${selected.id === f.id ? 'card-glow-blue' : ''}`}
                style={{
                  cursor: 'pointer', padding: 16,
                  borderColor: selected.id === f.id ? f.color : undefined,
                  borderWidth: selected.id === f.id ? 1 : undefined,
                }}
                onClick={() => setSelected(f)}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                  <span style={{ fontSize: 22 }}>{f.icon}</span>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>{f.name}</div>
                    <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>{f.checks} policies</div>
                  </div>
                </div>
                <div style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>{f.desc}</div>
              </div>
            ))}
          </div>

          {/* Policy detail */}
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
              <span style={{ fontSize: 32 }}>{selected.icon}</span>
              <div>
                <h2 style={{ fontSize: 18, fontWeight: 700 }}>{selected.name}</h2>
                <p style={{ color: 'var(--color-text-muted)', fontSize: 13 }}>{selected.desc}</p>
              </div>
              <span className="badge success" style={{ marginLeft: 'auto' }}>Active</span>
            </div>

            <table className="data-table">
              <thead>
                <tr>
                  <th>Policy ID</th>
                  <th>Name</th>
                  <th>Resource Type</th>
                  <th>Severity</th>
                  <th>Engine</th>
                </tr>
              </thead>
              <tbody>
                {selected.policies.map(p => (
                  <tr key={p.id}>
                    <td style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--color-text-muted)' }}>{p.id}</td>
                    <td style={{ fontWeight: 500 }}>{p.name}</td>
                    <td style={{ color: 'var(--color-text-muted)', fontSize: 13 }}>{p.resource_type}</td>
                    <td><span className={`badge ${p.severity}`}>{p.severity}</span></td>
                    <td>
                      <span style={{ fontSize: 11, background: 'rgba(106,90,205,0.15)', color: '#a78bfa', padding: '3px 8px', borderRadius: 4, fontWeight: 600 }}>
                        OPA + YAML
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}
