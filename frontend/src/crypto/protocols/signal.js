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

// Simplified Signal: X3DH (without identity-key signature verification fancy parts)
// + Double Ratchet (DH ratchet + symmetric chain ratchet).
//
// X3DH (initiator side, when starting a new session):
//   - Fetch Bob's prekey bundle: IK_B, SPK_B, sig_IK_B(SPK_B), OPK_B (optional)
//   - Generate ephemeral EK_A
//   - SK = KDF( DH(IK_A, SPK_B) || DH(EK_A, IK_B) || DH(EK_A, SPK_B) [|| DH(EK_A, OPK_B)] )
//   - First message carries (IK_A, EK_A, opk_id) so Bob can derive the same SK.
//
// Double Ratchet:
//   - Each side has DH key pair, RK (root key), CK_send/CK_recv.
//   - On receiving a message with a new remote DH pub: perform DH ratchet step (advance RK, derive new CK_recv, generate new local DH, advance RK again, derive new CK_send).
//   - For each outgoing message: derive (CK_send, MK) = KDF_CK(CK_send), encrypt with MK, send header { dh_pub, n, pn }.

export const NAME = 'signal'

const INFO_ROOT = utf8('Signal-DR-Root')
const INFO_CHAIN = new Uint8Array([0x02])
const INFO_MSG = new Uint8Array([0x01])

function kdfRoot(rk, dhOut) {
  const out = hkdf(rk, dhOut, INFO_ROOT, 64)
  return { rk: out.subarray(0, 32), ck: out.subarray(32, 64) }
}

function kdfChain(ck) {
  // mk = HMAC(ck, 0x01), ck' = HMAC(ck, 0x02)
  const mk = sodium.crypto_auth_hmacsha256(INFO_MSG, ck)
  const ckNext = sodium.crypto_auth_hmacsha256(INFO_CHAIN, ck)
  return { mk, ckNext }
}

// ----- session creation -----

export function createSession({ me, peer, role, x3dh }) {
  // role: 'initiator' or 'responder'
  // x3dh: shared output of X3DH (32 bytes)
  // For initiator: also includes their EK, peer bundle, etc — packed into first message.
  return {
    protocol: NAME,
    role,
    me,
    peer,

    // Long-term identity key (X25519)
    IK_priv: me.identityKeyPair.privateKey,
    IK_pub: me.identityKeyPair.publicKey,

    // X3DH-derived shared secret used as initial RK
    rk: x3dh.SK,
    // Chain keys come from the first DH ratchet performed inside X3DH.
    // Initiator: ck_send is ready (uses EK pair); Bob will set ck_recv on first inbound.
    // Responder: ck_recv is ready (uses SPK pair); will generate ck_send on first outbound.
    ck_send: x3dh.ck_send ?? null,
    ck_recv: x3dh.ck_recv ?? null,

    // DH ratchet keys
    dh_priv: x3dh.initialDh?.privateKey ?? null,
    dh_pub: x3dh.initialDh?.publicKey ?? null,
    remote_dh: x3dh.remoteDh ?? null,

    n_send: 0,
    n_recv: 0,
    pn: 0,

    // X3DH preamble that must be attached to the FIRST outgoing message (initiator only)
    pendingX3dhPreamble: x3dh.preamble ?? null,

    established: true,
    needsHandshake: false,
  }
}

// ----- X3DH helpers -----

// Initiator computes SK + builds preamble to send with first message.
export function initiatorX3DH(me, bundle) {
  // bundle: { identity_key, signed_prekey, signed_prekey_sig, one_time_prekey? }
  const IK_B = B64.decode(bundle.identity_key)
  const SPK_B = B64.decode(bundle.signed_prekey)
  const OPK_B = bundle.one_time_prekey ? B64.decode(bundle.one_time_prekey.public_key) : null

  const EK = generateX25519()

  const dh1 = dh(me.identityKeyPair.privateKey, SPK_B) // DH(IK_A, SPK_B)
  const dh2 = dh(EK.privateKey, IK_B)                  // DH(EK_A, IK_B)
  const dh3 = dh(EK.privateKey, SPK_B)                 // DH(EK_A, SPK_B)
  const dh4 = OPK_B ? dh(EK.privateKey, OPK_B) : null  // DH(EK_A, OPK_B)

  const ikm = dh4 ? concat(dh1, dh2, dh3, dh4) : concat(dh1, dh2, dh3)
  const SK = hkdf(new Uint8Array(32), ikm, utf8('Signal-X3DH'), 32)

  // Initial DR setup: initiator's first DH key pair = EK (re-used).
  // We perform the first DH ratchet immediately with Bob's signed prekey,
  // so ck_send is ready before Bob's response arrives.
  const initialDh = EK
  const remoteDh = SPK_B

  const firstRatchet = kdfRoot(SK, dh(initialDh.privateKey, remoteDh))

  return {
    SK: firstRatchet.rk,         // rk after the initial DH ratchet
    ck_send: firstRatchet.ck,
    ck_recv: null,
    initialDh,
    remoteDh,
    preamble: {
      IK: B64.encode(me.identityKeyPair.publicKey),
      EK: B64.encode(EK.publicKey),
      opk_id: bundle.one_time_prekey ? bundle.one_time_prekey.key_id : null,
    },
  }
}

// Responder, when first inbound message arrives with preamble, derives the same SK.
export function responderX3DH(me, preamble, spkPair, opkPair) {
  // spkPair: { publicKey, privateKey } — responder's signed prekey pair
  // opkPair: { publicKey, privateKey } or null
  const IK_A = B64.decode(preamble.IK)
  const EK_A = B64.decode(preamble.EK)

  const dh1 = dh(spkPair.privateKey, IK_A)              // DH(SPK_B, IK_A) = DH(IK_A, SPK_B)
  const dh2 = dh(me.identityKeyPair.privateKey, EK_A)    // DH(IK_B, EK_A) = DH(EK_A, IK_B)
  const dh3 = dh(spkPair.privateKey, EK_A)               // DH(SPK_B, EK_A) = DH(EK_A, SPK_B)
  const dh4 = opkPair ? dh(opkPair.privateKey, EK_A) : null

  const ikm = dh4 ? concat(dh1, dh2, dh3, dh4) : concat(dh1, dh2, dh3)
  const SK = hkdf(new Uint8Array(32), ikm, utf8('Signal-X3DH'), 32)

  // Mirror initiator's "first DH ratchet" using SPK as our DH key + EK_A as remote.
  const firstRatchet = kdfRoot(SK, dh(spkPair.privateKey, EK_A))

  return {
    SK: firstRatchet.rk,
    ck_send: null,
    ck_recv: firstRatchet.ck,
    initialDh: spkPair, // until we generate a new one on first send
    remoteDh: EK_A,
  }
}

// ----- transport -----

export function encrypt(session, plaintext) {
  if (!session.ck_send) {
    // Need to perform a DH ratchet on send (we just received a remote DH).
    const newDh = generateX25519()
    const { rk, ck } = kdfRoot(session.rk, dh(newDh.privateKey, session.remote_dh))
    session.rk = rk
    session.ck_send = ck
    session.pn = session.n_send
    session.n_send = 0
    session.dh_priv = newDh.privateKey
    session.dh_pub = newDh.publicKey
  }
  const { mk, ckNext } = kdfChain(session.ck_send)
  session.ck_send = ckNext

  // AEAD encrypt
  const nonce = counterNonce(session.n_send)
  const header = {
    dh: B64.encode(session.dh_pub),
    n: session.n_send,
    pn: session.pn,
  }
  const aad = utf8(JSON.stringify(header))
  const ct = aeadEncrypt(mk, nonce, utf8(plaintext), aad)
  session.n_send += 1

  const payload = { header, ct: B64.encode(ct) }
  if (session.pendingX3dhPreamble) {
    payload.x3dh = session.pendingX3dhPreamble
    session.pendingX3dhPreamble = null
  }

  const fields = []
  if (payload.x3dh) {
    fields.push({ label: 'X3DH.IK_A', value: payload.x3dh.IK, color: 'static', bytes: 32 })
    fields.push({ label: 'X3DH.EK_A', value: payload.x3dh.EK, color: 'eph', bytes: 32 })
    fields.push({ label: 'X3DH.opk_id', value: String(payload.x3dh.opk_id), color: 'meta', bytes: null })
  }
  fields.push({ label: 'header.dh', value: header.dh, color: 'eph', bytes: 32 })
  fields.push({ label: 'header.n', value: String(header.n), color: 'nonce', bytes: 4 })
  fields.push({ label: 'header.pn', value: String(header.pn), color: 'nonce', bytes: 4 })
  fields.push({ label: 'ct + AEAD tag', value: payload.ct, color: 'ct', bytes: ct.length })

  return {
    payload,
    wire: {
      stage: payload.x3dh ? 'initial (X3DH + DR)' : 'DR message',
      fields,
      note: payload.x3dh
        ? '첫 메시지: X3DH preamble + 첫 ratchet 결과로 암호화.'
        : `같은 DH ratchet 내부 n=${header.n}, MK는 즉시 폐기 (FS).`,
    },
  }
}

export function decrypt(session, payload) {
  // If preamble present + we have not initialized recv yet, the X3DH already happened
  // via session creation (responder). preamble is informational here.
  const header = payload.header
  const remoteDhB64 = header.dh
  const remoteDhBytes = B64.decode(remoteDhB64)

  let didRatchet = false
  // Detect new remote DH pub → DH ratchet step.
  const currentRemote = session.remote_dh ? B64.encode(session.remote_dh) : null
  if (currentRemote !== remoteDhB64) {
    didRatchet = true
    // ratchet: advance with new remote DH
    const { rk: rk1, ck: ck1 } = kdfRoot(session.rk, dh(session.dh_priv, remoteDhBytes))
    session.rk = rk1
    session.ck_recv = ck1
    session.remote_dh = remoteDhBytes

    // Generate new local DH and advance RK again to set up next ck_send
    const newDh = generateX25519()
    const { rk: rk2, ck: ck2 } = kdfRoot(session.rk, dh(newDh.privateKey, remoteDhBytes))
    session.rk = rk2
    session.ck_send = ck2
    session.pn = session.n_send
    session.n_send = 0
    session.n_recv = 0
    session.dh_priv = newDh.privateKey
    session.dh_pub = newDh.publicKey
  }

  // Skip-message handling (out-of-order) is omitted for brevity. We assume in-order delivery.
  // Advance recv chain until n_recv == header.n
  let mk
  while (session.n_recv <= header.n) {
    const r = kdfChain(session.ck_recv)
    mk = r.mk
    session.ck_recv = r.ckNext
    session.n_recv += 1
    if (session.n_recv > header.n + 1) break
  }

  const aad = utf8(JSON.stringify(header))
  const nonce = counterNonce(header.n)
  const pt = aeadDecrypt(mk, nonce, B64.decode(payload.ct), aad)

  const fields = [
    { label: 'header.dh (remote)', value: header.dh, color: 'eph', bytes: 32 },
    { label: 'header.n', value: String(header.n), color: 'nonce', bytes: 4 },
    { label: 'header.pn', value: String(header.pn), color: 'nonce', bytes: 4 },
    { label: 'ct + AEAD tag', value: payload.ct, color: 'ct', bytes: B64.decode(payload.ct).length },
  ]

  return {
    plaintext: sodium.to_string(pt),
    wire: {
      stage: didRatchet ? 'DR message (새 DH ratchet 발생)' : 'DR message',
      fields,
      note: didRatchet
        ? '새 remote DH pub 감지 → root key 한 단계 진행, ck 갱신.'
        : `n=${header.n}, MK 사용 후 폐기.`,
    },
  }
}

// no-op: Signal session is fully built via X3DH at createSession time.
export function startHandshake() {
  return null
}
export function handleHandshake() {
  return { done: true }
}
