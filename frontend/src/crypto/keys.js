import sodium from 'libsodium-wrappers'

// X25519 keypair lifecycle.
//
// On first login we generate a Curve25519 keypair. The private key is kept
// in localStorage on the client; the public key is uploaded to the server
// so other clients can encrypt messages to us. The server never sees the
// private key, so it cannot read message contents.
//
// NOTE — for a learning project this is fine. For production you would:
//   - protect the private key with a passphrase / WebCrypto-derived KEK
//   - use ephemeral keys (Double Ratchet) for forward secrecy
//   - publish signed prekey bundles instead of a single static key

const STORAGE_PREFIX = 'e2ee-chat:'

export async function initSodium() {
  await sodium.ready
  return sodium
}

function storageKey(username) {
  return `${STORAGE_PREFIX}${username}:keypair`
}

export async function loadOrCreateKeypair(username) {
  await sodium.ready
  const existing = localStorage.getItem(storageKey(username))
  if (existing) {
    const parsed = JSON.parse(existing)
    return {
      publicKey: sodium.from_base64(parsed.publicKey, sodium.base64_variants.ORIGINAL),
      privateKey: sodium.from_base64(parsed.privateKey, sodium.base64_variants.ORIGINAL),
      publicKeyB64: parsed.publicKey,
    }
  }
  const kp = sodium.crypto_box_keypair()
  const publicKeyB64 = sodium.to_base64(kp.publicKey, sodium.base64_variants.ORIGINAL)
  const privateKeyB64 = sodium.to_base64(kp.privateKey, sodium.base64_variants.ORIGINAL)
  localStorage.setItem(
    storageKey(username),
    JSON.stringify({ publicKey: publicKeyB64, privateKey: privateKeyB64 }),
  )
  return {
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
    publicKeyB64,
  }
}

export function clearKeypair(username) {
  localStorage.removeItem(storageKey(username))
}
