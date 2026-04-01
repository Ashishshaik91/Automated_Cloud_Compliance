import React, { useState, useEffect, useCallback } from 'react'
import axios from 'axios'
import TerminalWindow from '../components/TerminalWindow'

const API = (token) => axios.create({
  headers: { Authorization: `Bearer ${token}` }
})

const ROLE_COLORS = {
  admin:   'var(--color-danger)',
  auditor: 'var(--color-warning)',
  dev:     'var(--color-accent)',
  viewer:  'var(--color-text-dim)',
}

const ROLE_DESCRIPTIONS = {
  admin:   'root_access',
  auditor: 'compliance_audit',
  dev:     'read_only_dev',
  viewer:  'restricted_view',
}

function RoleBadge({ role }) {
  const color = ROLE_COLORS[role] || '#6272a4'
  return (
    <span style={{
      display: 'inline-block', padding: '0px 6px',
      fontSize: 9, fontWeight: 900, fontFamily: 'var(--font-mono)',
      color, border: `1px solid ${color}44`,
    }}>
      [{role?.toUpperCase()}]
    </span>
  )
}

function ExpiryBadge({ expiresAt }) {
  if (!expiresAt) return <span style={{ color: 'var(--color-success)', fontSize: 10, fontFamily: 'var(--font-mono)' }}>[PERMANENT]</span>
  const expires = new Date(expiresAt)
  const now = new Date()
  const diffMs = expires - now
  if (diffMs <= 0) return <span style={{ color: 'var(--color-danger)', fontSize: 10, fontWeight: 900, fontFamily: 'var(--font-mono)' }}>[EXPIRED]</span>
  const label = new Date(expiresAt).toISOString().split('T')[0]
  return <span style={{ color: 'var(--color-warning)', fontSize: 10, fontFamily: 'var(--font-mono)' }}>[EXP: {label}]</span>
}

export default function Admin() {
  const token = localStorage.getItem('access_token')
  const [tab, setTab] = useState('users')
  const [users, setUsers] = useState([])
  const [auditLogs, setAuditLogs] = useState([])
  const [userRoles, setUserRoles] = useState({})
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const [form, setForm] = useState({ email: '', full_name: '', password: '', role: 'dev' })
  const [assignForm, setAssignForm] = useState({ user_id: '', cloud_account_id: '', role: 'dev', expires_at: '' })

  const api = API(token)

  const fetchUsers = useCallback(async () => {
    try {
      const res = await api.get('/api/v1/users/')
      setUsers(res.data)
    } catch {}
  }, [token])

  const fetchAuditLogs = useCallback(async () => {
    try {
      const res = await api.get('/api/v1/audit-logs/?limit=50')
      setAuditLogs(res.data)
    } catch {}
  }, [token])

  const fetchUserRoles = useCallback(async (userId) => {
    try {
      const res = await api.get(`/api/v1/users/${userId}/roles`)
      setUserRoles(prev => ({ ...prev, [userId]: res.data }))
    } catch {}
  }, [token])

  useEffect(() => {
    fetchUsers()
    fetchAuditLogs()
  }, [fetchUsers, fetchAuditLogs])

  const createUser = async (e) => {
    e.preventDefault()
    setLoading(true); setError(''); setSuccess('')
    try {
      await api.post('/api/v1/users/', form)
      setSuccess('SYSTEM_MESSAGE: USER_CREATED_SUCCESS')
      setForm({ email: '', full_name: '', password: '', role: 'dev' })
      fetchUsers()
    } catch (err) {
      setError(err.response?.data?.detail || 'ERR: CREATION_FAILED')
    } finally { setLoading(false) }
  }

  const deactivateUser = async (userId) => {
    if (!window.confirm('[ WARNING ] SHUTTING DOWN USER ACCESS. PROCEED?')) return
    try {
      await api.patch(`/api/v1/users/${userId}/deactivate`)
      fetchUsers()
    } catch (err) { setError(err.response?.data?.detail || 'ERR: DEACTIVATION_FAILED') }
  }

  const assignRole = async (e) => {
    e.preventDefault()
    setError(''); setSuccess('')
    const body = {
      user_id: parseInt(assignForm.user_id),
      cloud_account_id: parseInt(assignForm.cloud_account_id),
      role: assignForm.role,
      expires_at: assignForm.expires_at || null,
    }
    try {
      await api.post(`/api/v1/users/${assignForm.user_id}/roles`, body)
      setSuccess('SYSTEM_MESSAGE: ROLE_ASSIGNED')
      fetchUserRoles(assignForm.user_id)
    } catch (err) { setError(err.response?.data?.detail || 'ERR: ASSIGNMENT_FAILED') }
  }

  const revokeRole = async (userId, accountId) => {
    if (!window.confirm('[ WARNING ] REVOKING PRIVILEGE. PROCEED?')) return
    try {
      await api.delete(`/api/v1/users/${userId}/roles/${accountId}`)
      fetchUserRoles(userId)
    } catch (err) { setError(err.response?.data?.detail || 'ERR: REVOCATION_FAILED') }
  }

  const inputStyle = {
    background: 'rgba(255,255,255,0.05)', border: '1px solid var(--color-border)',
    color: 'var(--color-text)', padding: '8px', fontSize: 12, fontFamily: 'var(--font-mono)', outline: 'none', width: '100%'
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div style={{ borderBottom: '1px solid var(--color-border)', paddingBottom: 16 }}>
        <div style={{ fontSize: 12, color: 'var(--color-primary)', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>$ sudo su - root</div>
        <div style={{ fontSize: 20, fontWeight: 900, fontFamily: 'var(--font-mono)' }}>kernel-control-center <span style={{ color: 'var(--color-danger)', fontWeight: 400 }}>--auth=root</span></div>
      </div>

      <div style={{ display: 'flex', gap: 12, fontFamily: 'var(--font-mono)' }}>
        {[
          { id: 'users', label: 'USER_MGMT' },
          { id: 'assign', label: 'ROLE_PROVISIONING' },
          { id: 'audit', label: 'AUDIT_TRAIL' }
        ].map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            background: tab === t.id ? 'var(--color-primary)' : 'rgba(255,255,255,0.05)',
            color: tab === t.id ? '#000' : 'var(--color-text)',
            border: 'none', padding: '6px 16px', cursor: 'pointer', fontSize: 11, fontWeight: 900,
            fontFamily: 'var(--font-mono)'
          }}>
            [{t.label}]
          </button>
        ))}
      </div>

      {error && <div style={{ background: 'rgba(255,85,85,0.1)', border: '1px solid var(--color-danger)', color: 'var(--color-danger)', padding: '10px', fontSize: 12, fontFamily: 'var(--font-mono)' }}>!! {error}</div>}
      {success && <div style={{ background: 'rgba(80,250,123,0.1)', border: '1px solid var(--color-success)', color: 'var(--color-success)', padding: '10px', fontSize: 12, fontFamily: 'var(--font-mono)' }}>** {success}</div>}

      {tab === 'users' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 24 }}>
          <TerminalWindow title="provision_new_user.conf">
            <form onSubmit={createUser} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 16, alignItems: 'flex-end', fontFamily: 'var(--font-mono)' }}>
              <div>
                <label style={{ fontSize: 10, color: 'var(--color-text-dim)', display: 'block', marginBottom: 6 }}>EMAIL_ID</label>
                <input style={inputStyle} type="email" required value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))} placeholder="user@root" />
              </div>
              <div>
                <label style={{ fontSize: 10, color: 'var(--color-text-dim)', display: 'block', marginBottom: 6 }}>FULL_NAME</label>
                <input style={inputStyle} required value={form.full_name} onChange={e => setForm(f => ({ ...f, full_name: e.target.value }))} placeholder="UID_001" />
              </div>
              <div>
                <label style={{ fontSize: 10, color: 'var(--color-text-dim)', display: 'block', marginBottom: 6 }}>ACCESS_KEY</label>
                <input style={inputStyle} type="password" required value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} placeholder="********" />
              </div>
              <div>
                <label style={{ fontSize: 10, color: 'var(--color-text-dim)', display: 'block', marginBottom: 6 }}>KERNEL_ROLE</label>
                <select style={inputStyle} value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value }))}>
                  {['admin', 'auditor', 'dev', 'viewer'].map(r => (
                    <option key={r} value={r} style={{background: '#1a1b26'}}>{r.toUpperCase()}</option>
                  ))}
                </select>
              </div>
              <button type="submit" disabled={loading} style={{ gridColumn: 'span 4', background: 'var(--color-primary)', border: 'none', padding: '10px', fontWeight: 900, cursor: 'pointer', fontFamily: 'var(--font-mono)', color: '#000' }}>
                {loading ? 'EXECUTING...' : '{">> "} COMMIT_USER_PROVISIONING'}
              </button>
            </form>
          </TerminalWindow>

          <TerminalWindow title="authorized_users_list.db">
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                <thead>
                  <tr style={{ textAlign: 'left', color: 'var(--color-info)', borderBottom: '1px solid var(--color-border)' }}>
                    <th style={{ padding: '10px 4px' }}>IDENTITY</th>
                    <th style={{ padding: '10px 4px' }}>ROLE</th>
                    <th style={{ padding: '10px 4px' }}>STATUS</th>
                    <th style={{ padding: '10px 4px' }}>VIRTUAL_UPLINKS</th>
                    <th style={{ padding: '10px 4px', textAlign: 'center' }}>ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map(u => (
                    <tr key={u.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                      <td style={{ padding: '12px 4px' }}>
                        <div style={{ fontWeight: 800 }}>{(u.full_name || 'UNKNOWN').toUpperCase()}</div>
                        <div style={{ color: 'var(--color-text-dim)', fontSize: 9 }}>{u.email}</div>
                      </td>
                      <td style={{ padding: '12px 4px' }}><RoleBadge role={u.role} /></td>
                      <td style={{ padding: '12px 4px', color: u.is_active ? 'var(--color-success)' : 'var(--color-danger)' }}>
                        {u.is_active ? '[ONLINE]' : '[DEAD_DROP]'}
                      </td>
                      <td style={{ padding: '12px 4px' }}>
                        {userRoles[u.id] ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                            {userRoles[u.id].map(ar => (
                              <div key={ar.id} style={{ fontSize: 9, display: 'flex', gap: 6 }}>
                                <span style={{ color: ROLE_COLORS[ar.role] }}>[{ar.role?.toUpperCase() || 'UNKNOWN'}]</span>
                                <span style={{ color: 'var(--color-text-dim)' }}>#ACC_{ar.cloud_account_id}</span>
                                <ExpiryBadge expiresAt={ar.expires_at} />
                              </div>
                            ))}
                            {userRoles[u.id].length === 0 && <span style={{ color: 'var(--color-text-dim)' }}>NO_SPECIFIC_ACL</span>}
                          </div>
                        ) : (
                          <button onClick={() => fetchUserRoles(u.id)} style={{ background: 'none', border: 'none', color: 'var(--color-primary)', cursor: 'pointer', fontSize: 9, padding: 0 }}>[QUERY_ACL_DATABASE]</button>
                        )}
                      </td>
                      <td style={{ padding: '12px 4px', textAlign: 'center' }}>
                        {u.is_active && (
                          <button onClick={() => deactivateUser(u.id)} style={{ background: 'none', border: 'none', color: 'var(--color-danger)', cursor: 'pointer', fontSize: 10, fontWeight: 900 }}>[KILL_SIGNAL]</button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </TerminalWindow>
        </div>
      )}

      {tab === 'assign' && (
        <TerminalWindow title="acl_provisioning_rules.yaml">
          <form onSubmit={assignRole} style={{ fontFamily: 'var(--font-mono)' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginBottom: 24 }}>
              <div>
                <label style={{ fontSize: 10, color: 'var(--color-text-dim)', display: 'block', marginBottom: 8 }}>TARGET_USER_UID</label>
                <input style={inputStyle} type="number" required value={assignForm.user_id} onChange={e => setAssignForm(f => ({ ...f, user_id: e.target.value }))} placeholder="0x02" />
              </div>
              <div>
                <label style={{ fontSize: 10, color: 'var(--color-text-dim)', display: 'block', marginBottom: 8 }}>TARGET_UPLINK_UID</label>
                <input style={inputStyle} type="number" required value={assignForm.cloud_account_id} onChange={e => setAssignForm(f => ({ ...f, cloud_account_id: e.target.value }))} placeholder="0x01" />
              </div>
              <div>
                <label style={{ fontSize: 10, color: 'var(--color-text-dim)', display: 'block', marginBottom: 8 }}>ELEVATED_ROLE</label>
                <select style={inputStyle} value={assignForm.role} onChange={e => setAssignForm(f => ({ ...f, role: e.target.value }))}>
                  {['admin', 'auditor', 'dev', 'viewer'].map(r => (
                    <option key={r} value={r} style={{background: '#1a1b26'}}>{r.toUpperCase()}</option>
                  ))}
                </select>
              </div>
              <div>
                <label style={{ fontSize: 10, color: 'var(--color-text-dim)', display: 'block', marginBottom: 8 }}>EXPIRATION_MARKER</label>
                <input style={inputStyle} type="datetime-local" value={assignForm.expires_at} onChange={e => setAssignForm(f => ({ ...f, expires_at: e.target.value }))} />
              </div>
            </div>
            <button type="submit" style={{ width: '100%', background: 'var(--color-primary)', color: '#000', border: 'none', padding: '12px', fontWeight: 900, fontSize: 12, fontFamily: 'var(--font-mono)', cursor: 'pointer' }}>
              {">> "} UPDATE_ACL_PERMISSIONS
            </button>
          </form>
        </TerminalWindow>
      )}

      {tab === 'audit' && (
        <TerminalWindow title="kernel_audit.log --tail 50">
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: 10 }}>
              <thead>
                <tr style={{ textAlign: 'left', color: 'var(--color-info)', borderBottom: '1px solid var(--color-border)' }}>
                  <th style={{ padding: '10px 4px' }}>TIMESTAMP</th>
                  <th style={{ padding: '10px 4px' }}>SUBJECT</th>
                  <th style={{ padding: '10px 4px' }}>SYSCALL</th>
                  <th style={{ padding: '10px 4px' }}>OBJECT</th>
                  <th style={{ padding: '10px 4px' }}>SOURCE_IP</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map(log => (
                  <tr key={log.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    <td style={{ padding: '8px 4px', color: 'var(--color-text-dim)' }}>
                      {new Date(log.timestamp).toISOString().replace('T', ' ').split('.')[0]}
                    </td>
                    <td style={{ padding: '8px 4px', fontWeight: 700 }}>{log.user_email}</td>
                    <td style={{ padding: '8px 4px' }}>
                      <span style={{ color: 'var(--color-accent)', fontWeight: 800 }}>{log.action?.toUpperCase() || 'ACTION'}</span>
                    </td>
                    <td style={{ padding: '8px 4px', color: 'var(--color-text-dim)' }}>
                      {log.resource_type?.toUpperCase() || 'RESOURCE'} {log.resource_id ? `[#${log.resource_id}]` : ''}
                    </td>
                    <td style={{ padding: '8px 4px', color: 'var(--color-text-dim)' }}>{log.ip_address || '127.0.0.1'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </TerminalWindow>
      )}
    </div>
  )
}
