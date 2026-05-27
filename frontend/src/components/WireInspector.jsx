import { useEffect, useRef } from 'react'

// Color palette per token type.
const COLORS = {
  ct: '#34d399',
  eph: '#fbbf24',
  static: '#22d3ee',
  derived: '#a78bfa',
  nonce: '#94a3b8',
  meta: '#64748b',
}

function trim(v, n = 28) {
  if (!v) return ''
  return v.length > n ? v.slice(0, n) + '…' : v
}

export default function WireInspector({ frames, onClear }) {
  const scrollRef = useRef(null)

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [frames])

  return (
    <div className="wire-inspector">
      <div className="wire-header">
        <div>
          <div className="wire-title">와이어 인스펙터</div>
          <div className="muted small">서버로 가는 / 서버에서 오는 실제 바이트</div>
        </div>
        <button onClick={onClear} className="link">초기화</button>
      </div>
      <div className="wire-frames" ref={scrollRef}>
        {frames.length === 0 && (
          <div className="muted small" style={{ padding: 12 }}>
            메시지를 보내면 여기에 표시됩니다.
          </div>
        )}
        {frames.map((f, i) => (
          <div key={i} className={`wire-frame ${f.direction}`}>
            <div className="wire-frame-head">
              <span className="wire-dir">
                {f.direction === 'outbound' ? '↗ 송신' : '↙ 수신'}
              </span>
              <span className="wire-proto">{f.protocol}</span>
              <span className="wire-stage">{f.wire.stage}</span>
            </div>
            <table className="wire-table">
              <tbody>
                {f.wire.fields.map((row, j) => (
                  <tr key={j}>
                    <td className="wire-label">{row.label}</td>
                    <td
                      className="wire-value"
                      style={{ color: COLORS[row.color] || '#cbd5e1' }}
                    >
                      {trim(String(row.value))}
                    </td>
                    <td className="wire-bytes">
                      {row.bytes != null ? `${row.bytes}B` : ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {f.wire.note && <div className="wire-note">{f.wire.note}</div>}
          </div>
        ))}
      </div>
    </div>
  )
}
