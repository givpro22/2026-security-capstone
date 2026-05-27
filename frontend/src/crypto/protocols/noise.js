import sodium from 'libsodium-wrappers'
import {
  B64,
  aeadDecrypt,
  aeadEncrypt,
  concat,
  counterNonce,
  dh,
  generateX25519,
  hkdf,
  utf8,
} from '../primitives'

// Noise XX, Curve25519, ChaCha20-Poly1305, SHA-256.
//
// Pattern:
//   -> e
//   <- e, ee, s, es
//   -> s, se
//
// After the 3 handshake messages, both sides derive k_send / k_recv via Split().
// All transport messages are AEAD-encrypted with a per-direction counter as nonce.

export const NAME = 'noise'
const PROTOCOL_NAME = utf8('Noise_XX_25519_ChaChaPoly_SHA256')
const EMPTY = new Uint8Array(0)

function sha256(data) {
  return sodium.crypto_hash_sha256(data)
}

// SymmetricState init
function initSymmetric() {
  // ck = h = SHA256(protocol_name) since name is exactly 32 bytes
  const h = PROTOCOL_NAME.length === 32 ? PROTOCOL_NAME : sha256(PROTOCOL_NAME)
  return {
    h: new Uint8Array(h),
    ck: new Uint8Array(h),
    k: null, // AEAD key once mixed
    n: 0n,
  }
}

function mixHash(ss, data) {
  ss.h = sha256(concat(ss.h, data))
}

function mixKey(ss, ikm) {
  const out = hkdf(ss.ck, ikm, EMPTY, 64)
  ss.ck = out.subarray(0, 32)
  ss.k = out.subarray(32, 64)
  ss.n = 0n
}

function encryptAndHash(ss, plaintext) {
  let ct
  if (ss.k) {
    ct = aeadEncrypt(ss.k, counterNonce(ss.n), plaintext, ss.h)
    ss.n += 1n
  } else {
    ct = plaintext
  }
  mixHash(ss, ct)
  return ct
}

function decryptAndHash(ss, ciphertext) {
  let pt
  if (ss.k) {
    pt = aeadDecrypt(ss.k, counterNonce(ss.n), ciphertext, ss.h)
    ss.n += 1n
  } else {
    pt = ciphertext
  }
  mixHash(ss, ciphertext)
  return pt
}

function split(ss) {
  const out = hkdf(ss.ck, EMPTY, EMPTY, 64)
  return {
    k1: out.subarray(0, 32),
    k2: out.subarray(32, 64),
  }
}

// ----- public API -----

export function createSession({ me, peer, role }) {
  // role: 'initiator' or 'responder'
  const ss = initSymmetric()
  // Pre-message: XX has no pre-message keys (unlike NK/IK), so just mix prologue = empty.
  return {
    protocol: NAME,
    role,
    ss,
    // long-term static keys (X25519). For XX both sides have one.
    s_priv: me.identityKeyPair.privateKey,
    s_pub: me.identityKeyPair.publicKey,
    // ephemeral keys filled during handshake
    e_priv: null,
    e_pub: null,
    re: null, // remote ephemeral
    rs: null, // remote static
    // transport state
    k_send: null,
    k_recv: null,
    n_send: 0n,
    n_recv: 0n,
    handshakeStage: 0, // 0 = nothing sent, 1 = msg1 done, 2 = msg2 done, 3 = msg3 done (complete)
    established: false,
    needsHandshake: true,
  }
}

// Initiator: build msg 1 (-> e)
export function startHandshake(session) {
  if (session.role !== 'initiator') return null
  const eph = generateX25519()
  session.e_priv = eph.privateKey
  session.e_pub = eph.publicKey

  mixHash(session.ss, session.e_pub)
  // payload empty
  const buf = concat(session.e_pub)
  session.handshakeStage = 1
  return {
    stage: 1,
    payload: { e: B64.encode(session.e_pub) },
    wire: {
      stage: 'handshake-1 (→ e)',
      fields: [
        { label: 'e (ephemeral pub)', value: B64.encode(session.e_pub), color: 'eph', bytes: 32 },
      ],
      note: 'Alice가 ephemeral 키 생성 후 공개키만 평문 전송.',
      raw: B64.encode(buf),
    },
  }
}

// Handle incoming handshake message based on current stage + role.
export function handleHandshake(session, incoming) {
  const stage = incoming.stage
  if (session.role === 'responder' && stage === 1) {
    // got -> e, now build <- e, ee, s, es
    session.re = B64.decode(incoming.payload.e)
    mixHash(session.ss, session.re)

    const eph = generateX25519()
    session.e_priv = eph.privateKey
    session.e_pub = eph.publicKey
    mixHash(session.ss, session.e_pub)

    mixKey(session.ss, dh(session.e_priv, session.re)) // ee

    const s_enc = encryptAndHash(session.ss, session.s_pub)
    mixKey(session.ss, dh(session.s_priv, session.re)) // es

    const payload_enc = encryptAndHash(session.ss, EMPTY) // empty payload but still AEAD

    session.handshakeStage = 2
    return {
      done: false,
      reply: {
        stage: 2,
        payload: {
          e: B64.encode(session.e_pub),
          s_ct: B64.encode(s_enc),
          payload_ct: B64.encode(payload_enc),
        },
        wire: {
          stage: 'handshake-2 (← e, ee, s, es)',
          fields: [
            { label: 'e (Bob ephemeral)', value: B64.encode(session.e_pub), color: 'eph', bytes: 32 },
            { label: 'ee mix', value: 'DH(e_A, e_B)', color: 'derived', bytes: null },
            { label: 's_ct (Bob static, encrypted)', value: B64.encode(s_enc), color: 'ct', bytes: s_enc.length },
            { label: 'es mix', value: 'DH(s_B, e_A)', color: 'derived', bytes: null },
            { label: 'payload_ct (+ AEAD tag)', value: B64.encode(payload_enc), color: 'ct', bytes: payload_enc.length },
          ],
          note: 'Bob: e 평문 + 자신의 정적키를 ee-파생키로 암호화하여 전달.',
        },
      },
    }
  }

  if (session.role === 'initiator' && stage === 2) {
    session.re = B64.decode(incoming.payload.e)
    mixHash(session.ss, session.re)
    mixKey(session.ss, dh(session.e_priv, session.re)) // ee

    const s_ct = B64.decode(incoming.payload.s_ct)
    session.rs = decryptAndHash(session.ss, s_ct)
    mixKey(session.ss, dh(session.e_priv, session.rs)) // es

    const payload_ct = B64.decode(incoming.payload.payload_ct)
    decryptAndHash(session.ss, payload_ct)

    // Now build msg 3: -> s, se
    const s_enc = encryptAndHash(session.ss, session.s_pub)
    mixKey(session.ss, dh(session.s_priv, session.re)) // se

    const payload_enc = encryptAndHash(session.ss, EMPTY)

    const { k1, k2 } = split(session.ss)
    // Initiator: k_send = k1, k_recv = k2
    session.k_send = k1
    session.k_recv = k2
    session.handshakeStage = 3
    session.established = true
    session.needsHandshake = false

    return {
      done: true,
      reply: {
        stage: 3,
        payload: {
          s_ct: B64.encode(s_enc),
          payload_ct: B64.encode(payload_enc),
        },
        wire: {
          stage: 'handshake-3 (→ s, se)',
          fields: [
            { label: 's_ct (Alice static, encrypted)', value: B64.encode(s_enc), color: 'ct', bytes: s_enc.length },
            { label: 'se mix', value: 'DH(s_A, e_B)', color: 'derived', bytes: null },
            { label: 'payload_ct', value: B64.encode(payload_enc), color: 'ct', bytes: payload_enc.length },
            { label: '→ k_send, k_recv 도출', value: 'Split(ck)', color: 'derived', bytes: 64 },
          ],
          note: 'Alice가 정적키 송신 후 split. 양쪽 transport key 확보.',
        },
      },
    }
  }

  if (session.role === 'responder' && stage === 3) {
    const s_ct = B64.decode(incoming.payload.s_ct)
    session.rs = decryptAndHash(session.ss, s_ct)
    mixKey(session.ss, dh(session.e_priv, session.rs)) // se

    const payload_ct = B64.decode(incoming.payload.payload_ct)
    decryptAndHash(session.ss, payload_ct)

    const { k1, k2 } = split(session.ss)
    // Responder: swapped
    session.k_send = k2
    session.k_recv = k1
    session.handshakeStage = 3
    session.established = true
    session.needsHandshake = false
    return { done: true }
  }

  throw new Error(`Noise: unexpected handshake stage ${stage} for role ${session.role}`)
}

// Transport
export function encrypt(session, plaintext) {
  if (!session.established) throw new Error('Noise handshake not complete')
  const nonce = counterNonce(session.n_send)
  const ct = aeadEncrypt(session.k_send, nonce, utf8(plaintext))
  const counter = session.n_send
  session.n_send += 1n
  const payload = { ct: B64.encode(ct), n: counter.toString() }
  return {
    payload,
    wire: {
      stage: 'transport',
      fields: [
        { label: 'counter (implicit nonce)', value: counter.toString(), color: 'nonce', bytes: 8 },
        { label: 'ct + AEAD tag', value: payload.ct, color: 'ct', bytes: ct.length },
      ],
      note: '헤더 없음. nonce는 양쪽이 카운트한 counter.',
    },
  }
}

export function decrypt(session, payload) {
  if (!session.established) throw new Error('Noise handshake not complete')
  const nonce = counterNonce(session.n_recv)
  const pt = aeadDecrypt(session.k_recv, nonce, B64.decode(payload.ct))
  const counter = session.n_recv
  session.n_recv += 1n
  return {
    plaintext: sodium.to_string(pt),
    wire: {
      stage: 'transport',
      fields: [
        { label: 'counter', value: counter.toString(), color: 'nonce', bytes: 8 },
        { label: 'ct + AEAD tag', value: payload.ct, color: 'ct', bytes: B64.decode(payload.ct).length },
      ],
    },
  }
}
