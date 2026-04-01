import React, { useState } from 'react'
import axios from 'axios'
import TerminalWindow from '../components/TerminalWindow'

export default function Login({ setToken }) {
  const [identity, setIdentity] = useState('')
  const [cypherKey, setCypherKey] = useState('')
  const [status, setStatus] = useState('IDLE')

  const handleEstablishLink = async (e) => {
    e.preventDefault()
    setStatus('LINK_INITIATED')
    try {
      // OAuth2PasswordRequestForm requires application/x-www-form-urlencoded
      const formData = new URLSearchParams()
      formData.append('username', identity)
      formData.append('password', cypherKey)
      const res = await axios.post('/api/v1/auth/login', formData, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      })
      setStatus('LINK_ESTABLISHED')
      // setToken (= App's login()) stores in localStorage AND updates
      // isAuthenticated state → App re-renders with the authenticated router.
      // No navigate() needed — and none possible (stale ref across router boundary).
      setTimeout(() => setToken(res.data.access_token), 600)
    } catch (err) {
      console.error(err)
      setStatus('LINK_FAILURE')
      setTimeout(() => setStatus('IDLE'), 2000)
    }
  }

  return (
    <div style={{ 
      height: '100vh', 
      display: 'flex', 
      alignItems: 'center', 
      justifyContent: 'center',
      position: 'relative',
      fontFamily: 'var(--font-main)',
      overflow: 'hidden'
    }}>
      <div style={{
        position: 'absolute',
        top: 0, left: 0, right: 0, bottom: 0,
        background: 'rgba(15, 10, 30, 0.4)',
        backdropFilter: 'blur(8px)'
      }} />

      <TerminalWindow 
        title="system_access_portal.sh"
        style={{ width: 400, zIndex: 10, background: 'rgba(15, 17, 26, 0.85)', backdropFilter: 'blur(10px)' }}
      >
        <div style={{ textAlign: 'center', marginBottom: 32, fontFamily: 'var(--font-mono)' }}>
          <pre style={{ 
            fontSize: 7, 
            color: 'var(--color-primary)', 
            lineHeight: 1.15, 
            margin: '0 auto 16px auto', 
            opacity: 0.9,
            fontFamily: 'var(--font-mono)',
            textAlign: 'left',
            width: 'fit-content'
          }}>
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
                           ;  `}<span style={{ color: 'var(--color-text-dim)' }}>bug</span>
          </pre>
          <h1 style={{ fontSize: 18, fontWeight: 900, color: 'var(--color-primary)', letterSpacing: 2, margin: 0 }}>
            DIREWOLF_SECURE
          </h1>
          <div style={{ fontSize: 9, color: 'var(--color-text-dim)', marginTop: 8 }}>
             [ UPLINK_AUTHORIZATION_REQUIRED ]
          </div>
        </div>

        <form onSubmit={handleEstablishLink} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div style={{ position: 'relative' }}>
            <label style={{ display: 'block', fontSize: 9, color: 'var(--color-text-dim)', marginBottom: 8, fontFamily: 'var(--font-mono)' }}>
              {'>>'} IDENTITY_ID_ROOT
            </label>
            <input
              type="text"
              placeholder="user@compliance.local"
              value={identity}
              onChange={(e) => setIdentity(e.target.value)}
              style={{
                width: '100%',
                background: 'rgba(255,255,255,0.03)',
                border: '1px solid var(--color-border)',
                padding: '12px',
                color: 'var(--color-text)',
                fontFamily: 'var(--font-mono)',
                fontSize: 13,
                outline: 'none',
                boxSizing: 'border-box'
              }}
              required
            />
          </div>

          <div style={{ position: 'relative' }}>
            <label style={{ display: 'block', fontSize: 9, color: 'var(--color-text-dim)', marginBottom: 8, fontFamily: 'var(--font-mono)' }}>
              {'>>'} CYPHER_KEY_ACCESS
            </label>
            <input
              type="password"
              placeholder="••••••••••••"
              value={cypherKey}
              onChange={(e) => setCypherKey(e.target.value)}
              style={{
                width: '100%',
                background: 'rgba(255,255,255,0.03)',
                border: '1px solid var(--color-border)',
                padding: '12px',
                color: 'var(--color-text)',
                fontFamily: 'var(--font-mono)',
                fontSize: 13,
                outline: 'none',
                boxSizing: 'border-box'
              }}
              required
            />
          </div>

          <button
            type="submit"
            disabled={status !== 'IDLE' && status !== 'LINK_FAILURE'}
            style={{
              marginTop: 10,
              padding: '14px',
              background: status === 'LINK_FAILURE' ? 'var(--color-danger)' : 'var(--color-primary)',
              color: '#000',
              border: 'none',
              fontWeight: 900,
              fontSize: 12,
              fontFamily: 'var(--font-mono)',
              cursor: 'pointer',
              transition: 'all 0.3s',
              opacity: status === 'LINK_INITIATED' ? 0.7 : 1
            }}
          >
            {status === 'IDLE' && '>> ESTABLISH_SECURE_LINK'}
            {status === 'LINK_INITIATED' && '>> INITIATING_UPLINK...'}
            {status === 'LINK_ESTABLISHED' && '>> ACCESS_GRANTED'}
            {status === 'LINK_FAILURE' && '>> ACCESS_DENIED_RETRY'}
          </button>
        </form>

        <div style={{ marginTop: 32, textAlign: 'center', fontSize: 8, color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)' }}>
          SECURE_ENCLAVE_ACTIVE // AES-256_GCM // DIREWOLF_PROTOCOL_V4
        </div>
      </TerminalWindow>
    </div>
  )
}
