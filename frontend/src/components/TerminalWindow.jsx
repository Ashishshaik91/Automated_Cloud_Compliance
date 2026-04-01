import React from 'react'

const TerminalWindow = ({ title, children, style, contentStyle, accent }) => {
  const borderColor = accent || 'var(--tui-border)'
  return (
    <div style={{
      position: 'relative',
      border: `1px solid ${borderColor}`,
      background: 'rgba(13, 10, 28, 0.72)',
      backdropFilter: 'blur(14px)',
      overflow: 'hidden',
      display: 'flex',
      flexDirection: 'column',
      ...style
    }}>
      {/* Top bar with box-drawing title */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        padding: '5px 10px',
        borderBottom: `1px solid ${borderColor}`,
        background: 'rgba(88, 54, 160, 0.18)',
        flexShrink: 0
      }}>
        {/* Traffic light dots */}
        <div style={{ display: 'flex', gap: 5, flexShrink: 0 }}>
          <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#ff5555', boxShadow: '0 0 6px #ff555588' }} />
          <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#f1fa8c', boxShadow: '0 0 6px #f1fa8c88' }} />
          <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#50fa7b', boxShadow: '0 0 6px #50fa7b88' }} />
        </div>
        <span style={{
          fontSize: 10,
          fontFamily: 'var(--font-mono)',
          color: borderColor,
          letterSpacing: '0.1em',
          opacity: 0.9,
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis'
        }}>
          ─ {title} ─
        </span>
      </div>
      <div style={{ padding: '12px 14px', overflow: 'auto', flex: 1, ...contentStyle }}>
        {children}
      </div>
    </div>
  )
}

export default TerminalWindow
