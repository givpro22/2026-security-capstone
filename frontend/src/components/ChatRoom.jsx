import { useEffect, useRef, useState } from 'react'
import { encryptMessage, decryptMessage } from '../crypto/session'
import { api } from '../api/client'

export default function ChatRoom({ me, peer, socket, onIncoming }) {
  const [messages, setMessages] = useState([])
  const [draft, setDraft] = useState('')
  const [error, setError] = useState('')
  // peer pub key — fetched once per peer change
  const peerPubRef = useRef(peer.public_key)
  const scrollRef = useRef(null)

  useEffect(() => {
    setMessages([])
    setError('')
    peerPubRef.current = peer.public_key
    // Refresh in case the peer rotated their key.
    api
      .getPublicKey(peer.username)
      .then((r) => (peerPubRef.current = r.public_key))
      .catch(() => {})
  }, [peer.username])

  // Subscribe to inbound messages from the parent's dispatcher.
  useEffect(() => {
    const unsubscribe = onIncoming((msg) => {
      if (msg.type === 'message' && msg.from === peer.username) {
        try {
          const plain = decryptMessage(
            msg.ciphertext,
            msg.nonce,
            peerPubRef.current,
            me.keypair.privateKey,
          )
          setMessages((prev) => [
            ...prev,
            { id: msg.id, from: msg.from, text: plain, mine: false },
          ])
        } catch (err) {
          setError('복호화 실패: ' + err.message)
        }
      }
    })
    return unsubscribe
  }, [peer.username, me.keypair.privateKey, onIncoming])

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [messages])

  function send() {
    if (!draft.trim()) return
    setError('')
    try {
      const { ciphertext, nonce } = encryptMessage(
        draft,
        peerPubRef.current,
        me.keypair.privateKey,
      )
      socket.send({
        type: 'message',
        to: peer.username,
        ciphertext,
        nonce,
      })
      setMessages((prev) => [
        ...prev,
        { id: `local-${Date.now()}`, from: me.username, text: draft, mine: true },
      ])
      setDraft('')
    } catch (err) {
      setError('암호화/전송 실패: ' + err.message)
    }
  }

  return (
    <div className="chat">
      <div className="chat-header">{peer.username} 와의 대화</div>
      <div className="chat-messages" ref={scrollRef}>
        {messages.length === 0 && (
          <div className="muted">첫 메시지를 보내보세요.</div>
        )}
        {messages.map((m) => (
          <div key={m.id} className={`msg ${m.mine ? 'mine' : 'theirs'}`}>
            {m.text}
          </div>
        ))}
        {error && <div className="error">{error}</div>}
      </div>
      <div className="chat-input">
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && send()}
          placeholder="메시지 입력 (Enter로 전송)"
        />
        <button onClick={send} disabled={!draft.trim()}>
          전송
        </button>
      </div>
    </div>
  )
}
