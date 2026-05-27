import sodium from 'libsodium-wrappers'
import { B64 } from '../primitives'

// Static long-term X25519 keys, libsodium crypto_box.
// No handshake — every message is a fresh nonce + ciphertext.

export const NAME = 'static'

export function createSession({ me, peer }) {
  // peer.public_key is base64 long-term X25519 pub.
  return {
    protocol: NAME,
    peerPubKey: B64.decode(peer.public_key),
    myPriv: me.identityKeyPair.privateKey,
    established: true,
    needsHandshake: false,
  }
}

export function encrypt(session, plaintext) {
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES)
  const ct = sodium.crypto_box_easy(
    sodium.from_string(plaintext),
    nonce,
    session.peerPubKey,
    session.myPriv,
  )
  const payload = { ct: B64.encode(ct), n: B64.encode(nonce) }
  return {
    payload,
    wire: {
      stage: 'message',
      fields: [
        { label: 'ciphertext', value: payload.ct, color: 'ct', bytes: ct.length },
        { label: 'nonce', value: payload.n, color: 'nonce', bytes: nonce.length },
      ],
      note: 'X25519 + XSalsa20-Poly1305. 키 재사용, FS 없음.',
    },
  }
}

export function decrypt(session, payload) {
  const ct = B64.decode(payload.ct)
  const nonce = B64.decode(payload.n)
  const plain = sodium.crypto_box_open_easy(ct, nonce, session.peerPubKey, session.myPriv)
  return {
    plaintext: sodium.to_string(plain),
    wire: {
      stage: 'message',
      fields: [
        { label: 'ciphertext', value: payload.ct, color: 'ct', bytes: ct.length },
        { label: 'nonce', value: payload.n, color: 'nonce', bytes: nonce.length },
      ],
    },
  }
}

// Static has no handshake — these are no-ops.
export function startHandshake() {
  return null
}
export function handleHandshake() {
  return { done: true }
}
