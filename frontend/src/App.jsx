import { useCallback, useEffect, useRef, useState } from 'react'
import Login from './components/Login'
import ChatList from './components/ChatList'
import ChatRoom from './components/ChatRoom'
import { api, loadToken, setToken, getToken } from './api/client'
import { initSodium, loadOrCreateKeypair, clearKeypair } from './crypto/keys'
import { connectSocket } from './api/socket'

export default function App() {
  const [me, setMe] = useState(null)        // { id, username, keypair }
  const [users, setUsers] = useState([])    // [{ username, public_key }]
  const [peer, setPeer] = useState(null)
  const [wsReady, setWsReady] = useState(false)

  const socketRef = useRef(null)
  const listenersRef = useRef(new Set())

  // Dispatcher every ChatRoom subscribes to.
  const onIncoming = useCallback((cb) => {
    listenersRef.current.add(cb)
    return () => listenersRef.current.delete(cb)
  }, [])

  // Restore session from localStorage on first load.
  useEffect(() => {
    const token = loadToken()
    if (!token) return
    ;(async () => {
      try {
        await initSodium()
        const profile = await api.me()
        const kp = await loadOrCreateKeypair(profile.username)
        // Make sure server has our current public key.
        if (profile.public_key !== kp.publicKeyB64) {
          await api.uploadPublicKey(kp.publicKeyB64)
        }
        setMe({ id: profile.id, username: profile.username, keypair: kp })
      } catch {
        setToken(null)
      }
    })()
  }, [])

  // Open WebSocket once we are authenticated.
  useEffect(() => {
    if (!me) return
    const sock = connectSocket(getToken(), {
      onOpen: () => setWsReady(true),
      onClose: () => setWsReady(false),
      onMessage: (data) => {
        for (const cb of listenersRef.current) cb(data)
      },
    })
    socketRef.current = sock
    return () => {
      sock.close()
      socketRef.current = null
    }
  }, [me])

  // Refresh the user list periodically while logged in.
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
