import * as staticProto from './protocols/static'
import * as noiseProto from './protocols/noise'
import * as signalProto from './protocols/signal'
import { api } from '../api/client'
import { B64, generateX25519, randomBytes } from './primitives'

const PROTOCOLS = {
  static: staticProto,
  noise: noiseProto,
  signal: signalProto,
}

// In-memory map: key = `${peerUsername}:${protocol}` → session object.
const sessions = new Map()

// Pending-handshake promise resolvers (Noise): once handshake completes we flush queued messages.
const pendingHandshakes = new Map() // key → { resolve, reject, promise, timer }

function registerPending(k, timeoutMs) {
  let resolve, reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  const timer = setTimeout(() => {
    if (pendingHandshakes.get(k)?.promise === promise) {
      pendingHandshakes.delete(k)
      reject(new Error('handshake timeout'))
    }
  }, timeoutMs)
  pendingHandshakes.set(k, { resolve, reject, promise, timer })
  return { promise }
}

function resolvePending(k) {
  const p = pendingHandshakes.get(k)
  if (!p) return
  clearTimeout(p.timer)
  pendingHandshakes.delete(k)
  p.resolve()
}

// Cached signed prekey + OPK private keys (Signal). Owned by the local user.
let myPrekeyState = null

export function getProtocol(name) {
  const p = PROTOCOLS[name]
  if (!p) throw new Error(`unknown protocol ${name}`)
  return p
}

function key(peer, protocol) {
  return `${peer}:${protocol}`
}

export function getSession(peer, protocol) {
  return sessions.get(key(peer, protocol)) || null
}

export function dropSession(peer, protocol) {
  sessions.delete(key(peer, protocol))
}

export function clearAllSessions() {
  sessions.clear()
  for (const p of pendingHandshakes.values()) clearTimeout(p.timer)
  pendingHandshakes.clear()
  myPrekeyState = null
}

// ---------- Signal prekey lifecycle ----------

export async function ensureMyPrekeys(me) {
  if (myPrekeyState) return myPrekeyState

  const stored = localStorage.getItem(`signal:${me.username}:prekeys`)
  if (stored) {
    const parsed = JSON.parse(stored)
    myPrekeyState = {
      spk: {
        publicKey: B64.decode(parsed.spk.publicKey),
        privateKey: B64.decode(parsed.spk.privateKey),
      },
      opks: parsed.opks.map((o) => ({
        key_id: o.key_id,
        publicKey: B64.decode(o.publicKey),
        privateKey: B64.decode(o.privateKey),
      })),
    }
  } else {
    const spk = generateX25519()
    const opks = []
    for (let i = 0; i < 8; i++) {
      const kp = generateX25519()
      opks.push({ key_id: i + 1, publicKey: kp.publicKey, privateKey: kp.privateKey })
    }
    myPrekeyState = { spk, opks }
    localStorage.setItem(
      `signal:${me.username}:prekeys`,
      JSON.stringify({
        spk: { publicKey: B64.encode(spk.publicKey), privateKey: B64.encode(spk.privateKey) },
        opks: opks.map((o) => ({
          key_id: o.key_id,
          publicKey: B64.encode(o.publicKey),
          privateKey: B64.encode(o.privateKey),
        })),
      }),
    )
  }

  // Publish to server (idempotent).
  try {
    // Signature: just sign the SPK pub with the user's identity key? We don't have ed25519.
    // For demo, the "signature" is a placeholder (32B random). Real Signal signs with Ed25519.
    const sigPlaceholder = B64.encode(randomBytes(64))
    await fetch('/keys/me/signed-prekey', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${localStorage.getItem('e2ee-chat:token')}`,
      },
      body: JSON.stringify({
        signed_prekey: B64.encode(myPrekeyState.spk.publicKey),
        signed_prekey_sig: sigPlaceholder,
      }),
    })
    await fetch('/keys/me/one-time-prekeys', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${localStorage.getItem('e2ee-chat:token')}`,
      },
      body: JSON.stringify({
        one_time_prekeys: myPrekeyState.opks.map((o) => ({
          key_id: o.key_id,
          public_key: B64.encode(o.publicKey),
        })),
      }),
    })
  } catch (e) {
    console.warn('prekey upload failed', e)
  }
  return myPrekeyState
}

function findOpkPrivate(opkId) {
  if (!myPrekeyState || opkId == null) return null
  const found = myPrekeyState.opks.find((o) => o.key_id === opkId)
  return found ? { publicKey: found.publicKey, privateKey: found.privateKey } : null
}

// ---------- session establishment ----------

/**
 * Ensure a session exists for (peer, protocol). For Noise, runs the handshake
 * by sending stage-1 and waiting for stage-2; returns once `established`.
 *
 * onWire: callback(direction, wireDescriptor) — called for each handshake msg sent/received.
 * sendOverSocket: function(payloadObj) — must send the JSON over WebSocket.
 */
export async function ensureSession({ me, peer, protocol, sendOverSocket, onWire }) {
  const k = key(peer.username, protocol)
  let sess = sessions.get(k)

  const proto = getProtocol(protocol)

  if (protocol === 'static') {
    // Static has no session state worth caching (no ratchet, no handshake).
    // Always fetch the peer's current public key so a stale cached value
    // (e.g., after the peer re-registered) can never cause a MAC failure.
    const pk = await api.getPublicKey(peer.username)
    sess = proto.createSession({
      me,
      peer: { username: peer.username, public_key: pk.public_key },
    })
    sessions.set(k, sess)
    return sess
  }

  if (sess && sess.established) return sess

  if (protocol === 'signal') {
    // Initiator side: fetch bundle, run X3DH, store session.
    await ensureMyPrekeys(me)
    const bundle = await api.getPrekeyBundle(peer.username)
    const x3dh = signalProto.initiatorX3DH(me, bundle)
    sess = proto.createSession({ me, peer, role: 'initiator', x3dh })
    sessions.set(k, sess)
    return sess
  }

  if (protocol === 'noise') {
    // 1. Already-established session: return immediately (handled by top guard,
    //    but kept here for clarity).
    if (sess && sess.established) return sess

    // 2. Handshake is currently in flight (we initiated previously, or we are
    //    a responder waiting for stage 3) — await that instead of starting a new one.
    if (pendingHandshakes.has(k)) {
      await pendingHandshakes.get(k).promise
      const after = sessions.get(k)
      if (after && after.established) return after
      throw new Error('Noise handshake timed out or failed')
    }

    // 3. If we are a responder mid-handshake (sess exists, role=responder,
    //    not established yet), we cannot send — we need stage 3 from initiator first.
    //    Register a pending so we wait for it.
    if (sess && sess.role === 'responder' && !sess.established) {
      const { promise } = registerPending(k, 5000)
      await promise
      const after = sessions.get(k)
      if (after && after.established) return after
      throw new Error('Noise handshake (responder) timed out')
    }

    // 4. Fresh initiator handshake. Drop any stale unestablished session first.
    if (sess) sessions.delete(k)
    sess = proto.createSession({ me, peer, role: 'initiator' })
    sessions.set(k, sess)
    const hs1 = proto.startHandshake(sess)
    onWire?.('outbound', hs1.wire)
    const { promise } = registerPending(k, 5000)
    sendOverSocket({
      type: 'handshake',
      to: peer.username,
      protocol: 'noise',
      stage: hs1.stage,
      payload: hs1.payload,
    })
    await promise
    const after = sessions.get(k)
    if (!after || !after.established) {
      throw new Error('Noise handshake did not complete')
    }
    return after
  }

  throw new Error(`unsupported protocol ${protocol}`)
}

// ---------- inbound dispatch ----------

/**
 * Called by App.jsx for every inbound socket frame.
 * Returns { plaintext, wire, from } for chat messages, or null for handshake frames.
 */
export async function handleInbound({ me, frame, sendOverSocket, onWire }) {
  if (frame.type === 'handshake' && frame.protocol === 'noise') {
    const k = key(frame.from, 'noise')
    let sess = sessions.get(k)
    if (!sess) {
      // We are the responder.
      sess = noiseProto.createSession({
        me,
        peer: { username: frame.from },
        role: 'responder',
      })
      sessions.set(k, sess)
    }
    const result = noiseProto.handleHandshake(sess, {
      stage: frame.stage,
      payload: frame.payload,
    })
    // Inbound wire for the message we just received:
    onWire?.('inbound', {
      stage: `handshake-${frame.stage} 받음`,
      fields: Object.entries(frame.payload).map(([k2, v]) => ({
        label: k2,
        value: typeof v === 'string' ? v : JSON.stringify(v),
        color: k2 === 'e' ? 'eph' : 'ct',
        bytes: null,
      })),
    })
    if (result.reply) {
      onWire?.('outbound', result.reply.wire)
      sendOverSocket({
        type: 'handshake',
        to: frame.from,
        protocol: 'noise',
        stage: result.reply.stage,
        payload: result.reply.payload,
      })
    }
    if (result.done) {
      // Both initiator (after sending stage 3) and responder (after receiving
      // stage 3) reach 'done' here — wake any awaiter for this peer.
      resolvePending(k)
    }
    return null
  }

  if (frame.type === 'message') {
    const protocol = frame.protocol || 'static'
    const k = key(frame.from, protocol)
    let sess = sessions.get(k)

    // Signal: any inbound message carrying an X3DH preamble means the peer is
    // (re-)establishing a session with us. Always build a fresh responder
    // session, replacing whatever we had — this resolves the case where
    // both sides initiated simultaneously OR one side reset their session.
    if (protocol === 'signal' && frame.payload?.x3dh) {
      await ensureMyPrekeys(me)
      const opkPair = findOpkPrivate(frame.payload.x3dh.opk_id)
      const x3dhState = signalProto.responderX3DH(
        me,
        frame.payload.x3dh,
        myPrekeyState.spk,
        opkPair,
      )
      sess = signalProto.createSession({
        me,
        peer: { username: frame.from },
        role: 'responder',
        x3dh: x3dhState,
      })
      sessions.set(k, sess)
    }

    // Static: always rebuild from current server-side pub key (cheap and
    // immune to stale peer-pub state).
    if (protocol === 'static') {
      const pk = await api.getPublicKey(frame.from)
      sess = staticProto.createSession({
        me,
        peer: { username: frame.from, public_key: pk.public_key },
      })
      sessions.set(k, sess)
    }

    if (!sess) throw new Error(`no session for ${frame.from}/${protocol}`)

    const proto = getProtocol(protocol)
    const { plaintext, wire } = proto.decrypt(sess, frame.payload)
    onWire?.('inbound', wire)
    return { plaintext, from: frame.from, protocol }
  }

  return null
}

// ---------- outbound ----------

export async function sendMessage({ me, peer, protocol, plaintext, sendOverSocket, onWire }) {
  const sess = await ensureSession({ me, peer, protocol, sendOverSocket, onWire })
  const proto = getProtocol(protocol)
  const { payload, wire } = proto.encrypt(sess, plaintext)
  onWire?.('outbound', wire)
  sendOverSocket({
    type: 'message',
    to: peer.username,
    protocol,
    payload,
  })
}
