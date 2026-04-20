import React, { useState, useEffect, useCallback } from 'react'
import { CheckCircle, XCircle, Clock, AlertTriangle, Send, RefreshCw, Play, X } from 'lucide-react'
import api from '../api/client'

const WF = '/workflows'  // base path — api client prepends /api/v1

// ── Status badge ────────────────────────────────────────────────────────────

const STATUS_STYLES = {
  pending:   { bg: 'rgba(234,179,8,0.15)',   color: '#f59e0b', icon: Clock },
  approved:  { bg: 'rgba(34,197,94,0.15)',   color: '#22c55e', icon: CheckCircle },
  rejected:  { bg: 'rgba(239,68,68,0.15)',   color: '#ef4444', icon: XCircle },
  cancelled: { bg: 'rgba(107,114,128,0.15)', color: '#6b7280', icon: X },
  expired:   { bg: 'rgba(107,114,128,0.15)', color: '#6b7280', icon: AlertTriangle },
  executed:  { bg: 'rgba(99,102,241,0.15)',  color: '#818cf8', icon: Play },
}

const RISK_STYLES = {
  critical: { color: '#ef4444' },
  high:     { color: '#f59e0b' },
  medium:   { color: '#60a5fa' },
}

function StatusBadge({ status }) {
  const s = STATUS_STYLES[status] || STATUS_STYLES.pending
  const Icon = s.icon
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '3px 10px', borderRadius: 20,
      background: s.bg, color: s.color,
      fontSize: 11, fontWeight: 700, fontFamily: 'var(--font-mono)',
      textTransform: 'uppercase', letterSpacing: 1,
    }}>
      <Icon size={11} /> {status}
    </span>
  )
}

// ── Submit modal ─────────────────────────────────────────────────────────────

function SubmitModal({ onClose, onSubmitted }) {
  const [form, setForm] = useState({
    title: '', description: '', action_type: 'remediation',
    risk_level: 'high', expiry_hours: 24,
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const submit = async () => {
    if (!form.title.trim()) { setError('Title is required'); return }
    setLoading(true); setError('')
    try {
      await api.post(`${WF}/requests`, form)
      onSubmitted()
      onClose()
    } catch (e) { setError(e.response?.data?.detail || e.message) }
    finally { setLoading(false) }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
    }}>
      <div style={{
        background: 'var(--color-surface)', border: '1px solid var(--color-border)',
        borderRadius: 12, padding: 28, width: 500, maxWidth: '95vw',
      }}>
        <h3 style={{ margin: '0 0 20px', color: 'var(--color-text)', fontSize: 16 }}>
          Submit Approval Request
        </h3>

        {error && (
          <div style={{ background: 'rgba(239,68,68,0.1)', color: '#ef4444', padding: '8px 12px', borderRadius: 6, marginBottom: 14, fontSize: 13 }}>
            {error}
          </div>
        )}

        {[
          { label: 'Title *', key: 'title', type: 'text' },
          { label: 'Description', key: 'description', type: 'textarea' },
        ].map(({ label, key, type }) => (
          <div key={key} style={{ marginBottom: 14 }}>
            <label style={{ display: 'block', fontSize: 12, color: 'var(--color-text-dim)', marginBottom: 4 }}>{label}</label>
            {type === 'textarea' ? (
              <textarea
                rows={3}
                value={form[key]}
                onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                style={{ width: '100%', background: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: 6, padding: '8px 10px', color: 'var(--color-text)', fontSize: 13, resize: 'vertical', boxSizing: 'border-box' }}
              />
            ) : (
              <input
                type="text"
                value={form[key]}
                onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                style={{ width: '100%', background: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: 6, padding: '8px 10px', color: 'var(--color-text)', fontSize: 13, boxSizing: 'border-box' }}
              />
            )}
          </div>
        ))}

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 20 }}>
          {[
            { label: 'Action Type', key: 'action_type', options: ['remediation','policy_change','account_delete','mfa_bypass'] },
            { label: 'Risk Level',  key: 'risk_level',  options: ['medium','high','critical'] },
            { label: 'Expires in (hrs)', key: 'expiry_hours', type: 'number' },
          ].map(({ label, key, options, type }) => (
            <div key={key}>
              <label style={{ display: 'block', fontSize: 12, color: 'var(--color-text-dim)', marginBottom: 4 }}>{label}</label>
              {options ? (
                <select value={form[key]} onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                  style={{ width: '100%', background: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: 6, padding: '7px 10px', color: 'var(--color-text)', fontSize: 13 }}>
                  {options.map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              ) : (
                <input type="number" min={1} max={168} value={form[key]}
                  onChange={e => setForm(f => ({ ...f, [key]: parseInt(e.target.value) || 24 }))}
                  style={{ width: '100%', background: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: 6, padding: '7px 10px', color: 'var(--color-text)', fontSize: 13, boxSizing: 'border-box' }}
                />
              )}
            </div>
          ))}
        </div>

        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{ padding: '8px 18px', borderRadius: 6, border: '1px solid var(--color-border)', background: 'transparent', color: 'var(--color-text-dim)', cursor: 'pointer', fontSize: 13 }}>
            Cancel
          </button>
          <button onClick={submit} disabled={loading} style={{ padding: '8px 18px', borderRadius: 6, border: 'none', background: 'var(--color-primary)', color: '#000', cursor: loading ? 'not-allowed' : 'pointer', fontSize: 13, fontWeight: 700, opacity: loading ? 0.6 : 1 }}>
            {loading ? 'Submitting...' : 'Submit Request'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Notes modal ──────────────────────────────────────────────────────────────

function NotesModal({ title, actionLabel, actionColor, onConfirm, onClose }) {
  const [notes, setNotes] = useState('')
  const [loading, setLoading] = useState(false)

  const confirm = async () => {
    setLoading(true)
    await onConfirm(notes)
    setLoading(false)
  }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1001 }}>
      <div style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 12, padding: 24, width: 380 }}>
        <h4 style={{ margin: '0 0 16px', color: 'var(--color-text)' }}>{title}</h4>
        <textarea rows={3} placeholder="Notes (optional)" value={notes} onChange={e => setNotes(e.target.value)}
          style={{ width: '100%', background: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: 6, padding: '8px 10px', color: 'var(--color-text)', fontSize: 13, resize: 'vertical', boxSizing: 'border-box', marginBottom: 16 }} />
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{ padding: '7px 16px', borderRadius: 6, border: '1px solid var(--color-border)', background: 'transparent', color: 'var(--color-text-dim)', cursor: 'pointer', fontSize: 13 }}>Cancel</button>
          <button onClick={confirm} disabled={loading} style={{ padding: '7px 16px', borderRadius: 6, border: 'none', background: actionColor, color: '#fff', cursor: loading ? 'not-allowed' : 'pointer', fontSize: 13, fontWeight: 700, opacity: loading ? 0.6 : 1 }}>
            {loading ? '...' : actionLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Request card ─────────────────────────────────────────────────────────────

function RequestCard({ req, role, myId, onRefresh }) {
  const [modal, setModal] = useState(null) // 'approve' | 'reject' | null
  const [actLoading, setActLoading] = useState(false)

  const act = async (endpoint, method = 'post', body = {}) => {
    setActLoading(true)
    try {
      await api[method](`${WF}/requests/${req.id}/${endpoint}`, body)
      onRefresh()
    } catch (e) { alert(e.response?.data?.detail || e.message) }
    finally { setActLoading(false) }
  }

  const riskStyle   = RISK_STYLES[req.risk_level] || RISK_STYLES.medium
  const isAdmin     = role === 'admin' || role === 'auditor'
  const isSelfOwned = myId && req.requester_id === myId

  return (
    <div style={{
      background: 'var(--color-surface)', border: '1px solid var(--color-border)',
      borderRadius: 10, padding: 18, marginBottom: 12,
      borderLeft: `3px solid ${riskStyle.color}`,
      transition: 'border-color 0.2s',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6, flexWrap: 'wrap' }}>
            <span style={{ fontWeight: 700, color: 'var(--color-text)', fontSize: 14, wordBreak: 'break-word' }}>{req.title}</span>
            <StatusBadge status={req.status} />
            <span style={{ fontSize: 11, color: riskStyle.color, fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
              [{req.risk_level?.toUpperCase()}]
            </span>
          </div>
          {req.description && (
            <p style={{ margin: '0 0 8px', color: 'var(--color-text-dim)', fontSize: 13, lineHeight: 1.5 }}>{req.description}</p>
          )}
          <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', flexWrap: 'wrap' }}>
            <span>TYPE: {req.action_type}</span>
            <span>REQUESTED: {new Date(req.requested_at).toLocaleString()}</span>
            {req.expires_at && <span>EXPIRES: {new Date(req.expires_at).toLocaleString()}</span>}
            {req.reviewed_at && <span>REVIEWED: {new Date(req.reviewed_at).toLocaleString()}</span>}
          </div>
          {req.notes && (
            <div style={{ marginTop: 8, padding: '6px 10px', background: 'rgba(255,255,255,0.03)', borderRadius: 6, fontSize: 12, color: 'var(--color-text-dim)', fontStyle: 'italic' }}>
              Note: {req.notes}
            </div>
          )}
        </div>

        {/* Actions */}
        {req.status === 'pending' && (
          <div style={{ display: 'flex', gap: 8, flexShrink: 0, flexWrap: 'wrap', alignItems: 'center' }}>
            {isAdmin && !isSelfOwned && (
              <>
                <button onClick={() => setModal('approve')} disabled={actLoading}
                  style={{ padding: '6px 14px', borderRadius: 6, border: 'none', background: 'rgba(34,197,94,0.15)', color: '#22c55e', cursor: 'pointer', fontSize: 12, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 5 }}>
                  <CheckCircle size={13} /> Approve
                </button>
                <button onClick={() => setModal('reject')} disabled={actLoading}
                  style={{ padding: '6px 14px', borderRadius: 6, border: 'none', background: 'rgba(239,68,68,0.15)', color: '#ef4444', cursor: 'pointer', fontSize: 12, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 5 }}>
                  <XCircle size={13} /> Reject
                </button>
              </>
            )}
            {isAdmin && isSelfOwned && (
              <span style={{ fontSize: 11, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)' }}>
                4-EYES: needs a second admin to review
              </span>
            )}
            <button onClick={() => act('cancel')} disabled={actLoading}
              style={{ padding: '6px 14px', borderRadius: 6, border: '1px solid var(--color-border)', background: 'transparent', color: 'var(--color-text-dim)', cursor: 'pointer', fontSize: 12, display: 'flex', alignItems: 'center', gap: 5 }}>
              <X size={13} /> Cancel
            </button>
          </div>
        )}

        {req.status === 'approved' && isAdmin && (
          <button onClick={() => act('execute')} disabled={actLoading}
            style={{ padding: '6px 14px', borderRadius: 6, border: 'none', background: 'rgba(99,102,241,0.2)', color: '#818cf8', cursor: 'pointer', fontSize: 12, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0 }}>
            <Play size={13} /> Execute
          </button>
        )}
      </div>

      {modal && (
        <NotesModal
          title={modal === 'approve' ? 'Approve Request' : 'Reject Request'}
          actionLabel={modal === 'approve' ? 'Approve' : 'Reject'}
          actionColor={modal === 'approve' ? '#22c55e' : '#ef4444'}
          onConfirm={async (notes) => { await act(modal, 'POST', { notes }); setModal(null) }}
          onClose={() => setModal(null)}
        />
      )}
    </div>
  )
}

// ── Main page ────────────────────────────────────────────────────────────────

export default function Workflows() {
  const [role, setRole]           = useState('')  // fetched from /auth/me
  const [myId, setMyId]           = useState(null)
  const [requests, setRequests]   = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [showSubmit, setShowSubmit] = useState(false)

  // Fetch authoritative role from backend — more reliable than JWT parsing
  useEffect(() => {
    api.get('/auth/me').then(r => {
      setRole(r.data.role || 'viewer')
      setMyId(r.data.id)
    }).catch(() => setRole('viewer'))
  }, [])

  const load = useCallback(async () => {
    setLoading(true); setError('')
    try {
      const qs = statusFilter ? `?status=${statusFilter}` : ''
      const res = await api.get(`${WF}/requests${qs}`)
      setRequests(Array.isArray(res.data) ? res.data : [])
    } catch (e) { setError(e.response?.data?.detail || e.message || 'Failed to load requests') }
    finally { setLoading(false) }
  }, [statusFilter])

  useEffect(() => { load() }, [load])

  const STATUS_FILTERS = ['', 'pending', 'approved', 'rejected', 'cancelled', 'expired', 'executed']

  const counts = requests.reduce((acc, r) => { acc[r.status] = (acc[r.status] || 0) + 1; return acc }, {})

  return (
    <div style={{ maxWidth: 900, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24, flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, color: 'var(--color-text)', fontWeight: 800 }}>Approval Workflows</h1>
          <p style={{ margin: '4px 0 0', color: 'var(--color-text-dim)', fontSize: 13 }}>
            4-eyes gate for high-risk platform actions
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button onClick={load} style={{ padding: '8px 14px', borderRadius: 6, border: '1px solid var(--color-border)', background: 'transparent', color: 'var(--color-text-dim)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
            <RefreshCw size={14} /> Refresh
          </button>
          <button onClick={() => setShowSubmit(true)} style={{ padding: '8px 18px', borderRadius: 6, border: 'none', background: 'var(--color-primary)', color: '#000', cursor: 'pointer', fontWeight: 700, fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
            <Send size={14} /> New Request
          </button>
        </div>
      </div>

      {/* Stats strip */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 20, flexWrap: 'wrap' }}>
        {[
          { label: 'Pending',  key: 'pending',  color: '#f59e0b' },
          { label: 'Approved', key: 'approved', color: '#22c55e' },
          { label: 'Rejected', key: 'rejected', color: '#ef4444' },
          { label: 'Executed', key: 'executed', color: '#818cf8' },
        ].map(({ label, key, color }) => (
          <div key={key} style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', borderRadius: 8, padding: '10px 18px', minWidth: 90, textAlign: 'center' }}>
            <div style={{ fontSize: 22, fontWeight: 800, color, fontFamily: 'var(--font-mono)' }}>{counts[key] || 0}</div>
            <div style={{ fontSize: 11, color: 'var(--color-text-dim)', textTransform: 'uppercase', letterSpacing: 1 }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Filter tabs */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 18, flexWrap: 'wrap' }}>
        {STATUS_FILTERS.map(s => (
          <button key={s || 'all'} onClick={() => setStatusFilter(s)}
            style={{
              padding: '5px 14px', borderRadius: 20, fontSize: 12, fontFamily: 'var(--font-mono)',
              border: '1px solid', cursor: 'pointer', textTransform: 'uppercase', letterSpacing: 0.5,
              borderColor: statusFilter === s ? 'var(--color-primary)' : 'var(--color-border)',
              background: statusFilter === s ? 'rgba(var(--color-primary-rgb),0.1)' : 'transparent',
              color: statusFilter === s ? 'var(--color-primary)' : 'var(--color-text-dim)',
            }}>
            {s || 'All'}
          </button>
        ))}
      </div>

      {/* Content */}
      {error && (
        <div style={{ background: 'rgba(239,68,68,0.1)', color: '#ef4444', padding: '12px 16px', borderRadius: 8, marginBottom: 16, fontSize: 14 }}>
          {error}
        </div>
      )}

      {loading ? (
        <div style={{ textAlign: 'center', padding: 60, color: 'var(--color-text-dim)', fontSize: 14 }}>Loading requests…</div>
      ) : requests.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 60, color: 'var(--color-text-dim)' }}>
          <Clock size={40} style={{ opacity: 0.3, marginBottom: 12, display: 'block', margin: '0 auto 12px' }} />
          <div style={{ fontSize: 15, fontWeight: 600 }}>No approval requests</div>
          <div style={{ fontSize: 13, marginTop: 6 }}>{statusFilter ? `No requests with status "${statusFilter}"` : 'Submit a new request to get started'}</div>
        </div>
      ) : (
        requests.map(req => (
          <RequestCard key={req.id} req={req} role={role} myId={myId} onRefresh={load} />
        ))
      )}

      {showSubmit && <SubmitModal onClose={() => setShowSubmit(false)} onSubmitted={load} />}
    </div>
  )
}
