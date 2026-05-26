import sodium from 'libsodium-wrappers'

// Per-message encryption helpers.
//
// We use crypto_box_easy (X25519 + XSalsa20-Poly1305). For each message we:
//   1. generate a fresh random nonce
//   2. compute ciphertext = box(message, nonce, recipientPub, senderPriv)
//   3. send {ciphertext, nonce} to the server, who relays it untouched
// The recipient does box_open(ciphertext, nonce, senderPub, recipientPriv).
//
// Properties this gives us:
//   - confidentiality + integrity (Poly1305 MAC)
//   - server cannot read messages
// What this does NOT give us:
//   - forward secrecy (one compromised private key decrypts all past messages)
//   - deniability / asynchronous prekeys
// Those would require Double Ratchet / X3DH (out of scope for now).

export function encryptMessage(plaintext, recipientPublicKeyB64, senderPrivateKey) {
  const recipientPub = sodium.from_base64(
    recipientPublicKeyB64,
    sodium.base64_variants.ORIGINAL,
  )
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES)
  const messageBytes = sodium.from_string(plaintext)
  const cipher = sodium.crypto_box_easy(messageBytes, nonce, recipientPub, senderPrivateKey)
  return {
    ciphertext: sodium.to_base64(cipher, sodium.base64_variants.ORIGINAL),
    nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
  }
}

export function decryptMessage(
  ciphertextB64,
  nonceB64,
  senderPublicKeyB64,
  recipientPrivateKey,
) {
  const cipher = sodium.from_base64(ciphertextB64, sodium.base64_variants.ORIGINAL)
  const nonce = sodium.from_base64(nonceB64, sodium.base64_variants.ORIGINAL)
  const senderPub = sodium.from_base64(
    senderPublicKeyB64,
    sodium.base64_variants.ORIGINAL,
  )
  const plain = sodium.crypto_box_open_easy(cipher, nonce, senderPub, recipientPrivateKey)
  return sodium.to_string(plain)
}
