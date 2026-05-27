import sodium from 'libsodium-wrappers'

// Low-level primitives shared by all three protocol implementations.
// Wraps libsodium so the protocol code reads more like the spec.

export const B64 = {
  encode: (bytes) => sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL),
  decode: (str) => sodium.from_base64(str, sodium.base64_variants.ORIGINAL),
}

export function randomBytes(n) {
  return sodium.randombytes_buf(n)
}

// X25519 key pair (Curve25519) — for both key agreement and signing-via-Ed25519 conversion if needed.
export function generateX25519() {
  // crypto_box_keypair gives X25519
  const kp = sodium.crypto_box_keypair()
  return { publicKey: kp.publicKey, privateKey: kp.privateKey }
}

// Ed25519 signing keypair (Signal needs to sign the SPK)
export function generateEd25519() {
  const kp = sodium.crypto_sign_keypair()
  return { publicKey: kp.publicKey, privateKey: kp.privateKey }
}

export function ed25519Sign(message, privateKey) {
  return sodium.crypto_sign_detached(message, privateKey)
}

export function ed25519Verify(signature, message, publicKey) {
  return sodium.crypto_sign_verify_detached(signature, message, publicKey)
}

// Diffie-Hellman over X25519. Returns 32-byte shared secret.
export function dh(myPrivate, theirPublic) {
  return sodium.crypto_scalarmult(myPrivate, theirPublic)
}

// HKDF-SHA256 using libsodium's BLAKE2b? No — sodium has crypto_kdf_hkdf_sha256 in recent versions.
// Fallback: build HKDF from HMAC-SHA256 ourselves.
// We use sodium.crypto_auth_hmacsha256 (HMAC-SHA256).
function hmacSha256(key, data) {
  return sodium.crypto_auth_hmacsha256(data, key)
}

export function hkdf(salt, ikm, info, length) {
  if (!salt || salt.length === 0) salt = new Uint8Array(32)
  const prk = hmacSha256(salt, ikm)
  const out = new Uint8Array(length)
  let prev = new Uint8Array(0)
  let written = 0
  let counter = 1
  while (written < length) {
    const buf = new Uint8Array(prev.length + info.length + 1)
    buf.set(prev, 0)
    buf.set(info, prev.length)
    buf[buf.length - 1] = counter
    prev = hmacSha256(prk, buf)
    const take = Math.min(prev.length, length - written)
    out.set(prev.subarray(0, take), written)
    written += take
    counter += 1
  }
  return out
}

// ChaCha20-Poly1305 AEAD. 12-byte nonce (IETF variant).
// Returns ciphertext || 16B tag.
export function aeadEncrypt(key, nonce12, plaintext, aad = null) {
  return sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
    plaintext,
    aad,
    null,
    nonce12,
    key,
  )
}

export function aeadDecrypt(key, nonce12, ciphertext, aad = null) {
  return sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    aad,
    nonce12,
    key,
  )
}

// Helpers
export function concat(...arrays) {
  let total = 0
  for (const a of arrays) total += a.length
  const out = new Uint8Array(total)
  let off = 0
  for (const a of arrays) {
    out.set(a, off)
    off += a.length
  }
  return out
}

export function utf8(s) {
  return sodium.from_string(s)
}
export function fromUtf8(b) {
  return sodium.to_string(b)
}

// Build a 12-byte IETF nonce from a 64-bit counter (zero-padded high bytes).
export function counterNonce(n) {
  const out = new Uint8Array(12)
  let x = BigInt(n)
  for (let i = 11; i >= 4; i--) {
    out[i] = Number(x & 0xffn)
    x >>= 8n
  }
  return out
}
