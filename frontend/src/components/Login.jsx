import { useState } from 'react'
import { api, setToken } from '../api/client'
import { initSodium, loadOrCreateKeypair } from '../crypto/keys'

export default function Login({ onAuthed }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [mode, setMode] = useState('login')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      await initSodium()
      const fn = mode === 'login' ? api.login : api.register
      const auth = await fn(username, password)
      setToken(auth.access_token)

      // Ensure keypair exists locally; upload pub key (idempotent).
      const kp = await loadOrCreateKeypair(auth.username)
      await api.uploadPublicKey(kp.publicKeyB64)

      onAuthed({
        id: auth.user_id,
        username: auth.username,
        keypair: kp,
      })
    } catch (err) {
      setError(err.message || String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="container">
      <div className="card" style={{ maxWidth: 360, margin: '64px auto' }}>
        <h2 style={{ marginTop: 0 }}>E2EE Chat</h2>
        <form className="col" onSubmit={submit}>
          <input
            placeholder="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoFocus
          />
          <input
            type="password"
            placeholder="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button type="submit" disabled={busy || !username || !password}>
            {busy ? '...' : mode === 'login' ? '로그인' : '회원가입'}
          </button>
          <button
            type="button"
            onClick={() => setMode(mode === 'login' ? 'register' : 'login')}
            style={{ background: 'transparent', color: '#2563eb' }}
          >
            {mode === 'login' ? '회원가입으로' : '로그인으로'}
          </button>
          {error && <div className="error">{error}</div>}
          <div className="muted">
            로그인 시 브라우저에 X25519 키페어가 생성/저장되고, 공개키만 서버에
            업로드됩니다.
          </div>
        </form>
      </div>
    </div>
  )
}
