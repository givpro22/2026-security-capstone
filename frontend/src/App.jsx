import { useCallback, useEffect, useRef, useState } from 'react'
import Login from './components/Login'
import ChatList from './components/ChatList'
import ChatRoom from './components/ChatRoom'
import { api, loadToken, setToken, getToken } from './api/client'
import { initSodium, loadOrCreateKeypair, clearKeypair } from './crypto/keys'
import { connectSocket } from './api/socket'
import { handleInbound, ensureMyPrekeys, clearAllSessions } from './crypto/sessionManager'

export default function App() {
  const [me, setMe] = useState(null)
  const [users, setUsers] = useState([])
  const [peer, setPeer] = useState(null)
  const [wsReady, setWsReady] = useState(false)

  const socketRef = useRef(null)
  // listenersRef now receives DECODED events: { kind: 'message'|'wire', from, ... }
  const listenersRef = useRef(new Set())

  const onIncoming = useCallback((cb) => {
    listenersRef.current.add(cb)
    return () => listenersRef.current.delete(cb)
  }, [])

  function emit(event) {
    for (const cb of listenersRef.current) cb(event)
  }

  useEffect(() => {
    const token = loadToken()
    if (!token) return
    ;(async () => {
      try {
        await initSodium()
        const profile = await api.me()
        const kp = await loadOrCreateKeypair(profile.username)
        if (profile.public_key !== kp.publicKeyB64) {
          await api.uploadPublicKey(kp.publicKeyB64)
        }
        setMe({
          id: profile.id,
          username: profile.username,
          keypair: kp,
          identityKeyPair: kp.identityKeyPair,
        })
      } catch {
        setToken(null)
      }
    })()
  }, [])

  // Single WebSocket; all crypto handled here so it works regardless of which
  // peer's chat is currently open.
  useEffect(() => {
    if (!me) return
    const sock = connectSocket(getToken(), {
      onOpen: () => setWsReady(true),
      onClose: () => setWsReady(false),
      onMessage: async (frame) => {
        try {
          const result = await handleInbound({
            me,
            frame,
            sendOverSocket: (p) => sock.send(p),
            onWire: (direction, wire) => {
              const from = frame.from || frame.to || null
              emit({ kind: 'wire', from, direction, wire, protocol: frame.protocol })
            },
          })
          if (result) {
            emit({
              kind: 'message',
              from: result.from,
              text: result.plaintext,
              protocol: result.protocol,
              id: frame.id,
            })
          }
        } catch (e) {
          console.error('inbound crypto error:', e)
          emit({ kind: 'error', from: frame.from, message: e.message })
        }
      },
    })
    socketRef.current = sock
    return () => {
      sock.close()
      socketRef.current = null
    }
  }, [me])

  // Publish Signal prekeys once authenticated, so peers can initiate X3DH with us.
  useEffect(() => {
    if (!me) return
    ensureMyPrekeys(me).catch((e) => console.warn('prekey publish failed:', e))
  }, [me])

  useEffect(() => {
    if (!me) return
    let cancelled = false
    async function refresh() {
      try {
        const list = await api.listUsers()
        if (!cancelled) setUsers(list)
      } catch {}
    }
    refresh()
    const id = setInterval(refresh, 5000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [me])

  function logout() {
    if (me) clearKeypair(me.username)
    clearAllSessions()
    setToken(null)
    setMe(null)
    setUsers([])
    setPeer(null)
    if (socketRef.current) socketRef.current.close()
  }

  if (!me) {
    return <Login onAuthed={setMe} />
  }

  return (
    <div className="container">
      <div style={{ marginBottom: 8 }} className="muted">
        WebSocket: {wsReady ? 'connected' : 'connecting...'}
      </div>
      <div className="layout">
        <ChatList
          users={users}
          selected={peer?.username}
          onSelect={setPeer}
          me={me}
          onLogout={logout}
        />
        {peer && socketRef.current ? (
          <ChatRoom
            key={peer.username}
            me={me}
            peer={peer}
            socket={socketRef.current}
            onIncoming={onIncoming}
          />
        ) : (
          <div className="card">왼쪽에서 대화 상대를 선택하세요.</div>
        )}
      </div>
    </div>
  )
}
