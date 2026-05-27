import { useEffect, useRef, useState } from 'react'
import WireInspector from './WireInspector'
import { sendMessage, dropSession } from '../crypto/sessionManager'

const PROTOCOLS = [
  { id: 'static', label: 'Static (X25519 box)' },
  { id: 'noise', label: 'Noise XX' },
  { id: 'signal', label: 'Signal (X3DH + DR)' },
]

export default function ChatRoom({ me, peer, socket, onIncoming }) {
  const [protocol, setProtocol] = useState('static')
  const [messages, setMessages] = useState([])
  const [draft, setDraft] = useState('')
  const [error, setError] = useState('')
  const [wireFrames, setWireFrames] = useState([])
  const [busy, setBusy] = useState(false)

  const scrollRef = useRef(null)

  useEffect(() => {
    setMessages([])
    setError('')
    setWireFrames([])
  }, [peer.username])

  // Subscribe to App-level decoded events. We filter by this peer.
  useEffect(() => {
    const unsubscribe = onIncoming((event) => {
      if (event.kind === 'message' && event.from === peer.username) {
        setMessages((prev) => [
          ...prev,
          {
            id: event.id,
            from: event.from,
            text: event.text,
            mine: false,
            protocol: event.protocol,
          },
        ])
      } else if (event.kind === 'wire' && event.from === peer.username) {
        setWireFrames((prev) => [
          ...prev,
          { direction: event.direction, wire: event.wire, protocol: event.protocol },
        ])
      } else if (event.kind === 'error' && event.from === peer.username) {
        setError('수신 처리 오류: ' + event.message)
      }
    })
    return unsubscribe
  }, [peer.username, onIncoming])

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [messages])

  function pushOwnWire(direction, wire) {
    setWireFrames((prev) => [...prev, { direction, wire, protocol }])
  }

  async function send() {
    if (!draft.trim() || busy) return
    setBusy(true)
    setError('')
    const text = draft
    setDraft('')
    try {
      await sendMessage({
        me,
        peer,
        protocol,
        plaintext: text,
        sendOverSocket: (p) => socket.send(p),
        onWire: pushOwnWire,
      })
      setMessages((prev) => [
        ...prev,
        { id: `local-${Date.now()}`, from: me.username, text, mine: true, protocol },
      ])
    } catch (e) {
      setError('전송 실패: ' + e.message)
    } finally {
      setBusy(false)
    }
  }

  function switchProtocol(newProto) {
    if (newProto === protocol) return
    setProtocol(newProto)
  }

  function resetSession() {
    dropSession(peer.username, protocol)
    setError(`${protocol} 세션 폐기됨. 다음 송신 시 새 세션.`)
  }

  return (
    <div className="chat-with-inspector">
      <div className="chat">
        <div className="chat-header">
          <span>{peer.username} 와의 대화</span>
          <div className="proto-controls">
            <select
              value={protocol}
              onChange={(e) => switchProtocol(e.target.value)}
            >
              {PROTOCOLS.map((p) => (
                <option key={p.id} value={p.id}>{p.label}</option>
              ))}
            </select>
            <button onClick={resetSession} className="ghost small" title="현재 프로토콜 세션 폐기">
              세션 리셋
            </button>
          </div>
        </div>
        <div className="chat-messages" ref={scrollRef}>
          {messages.length === 0 && (
            <div className="muted">첫 메시지를 보내보세요. 오른쪽에 와이어 데이터가 표시됩니다.</div>
          )}
          {messages.map((m) => (
            <div key={m.id} className={`msg ${m.mine ? 'mine' : 'theirs'}`}>
              <div className="msg-text">{m.text}</div>
              <div className="msg-proto">{m.protocol}</div>
            </div>
          ))}
          {error && <div className="error">{error}</div>}
        </div>
        <div className="chat-input">
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && send()}
            placeholder={`메시지 입력 (${protocol} 프로토콜)`}
            disabled={busy}
          />
          <button onClick={send} disabled={!draft.trim() || busy}>
            {busy ? '...' : '전송'}
          </button>
        </div>
      </div>
      <WireInspector frames={wireFrames} onClear={() => setWireFrames([])} />
    </div>
  )
}
