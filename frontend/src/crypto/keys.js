import sodium from 'libsodium-wrappers'

// Long-term X25519 identity keypair.
//
// All three protocols share this single long-term key:
//   - Static: used directly as the box keypair.
//   - Noise XX: the "s" (static) key in the handshake.
//   - Signal: the IK (identity key) in X3DH.
//
// Private key never leaves the browser (stored in localStorage).

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
    const publicKey = sodium.from_base64(parsed.publicKey, sodium.base64_variants.ORIGINAL)
    const privateKey = sodium.from_base64(parsed.privateKey, sodium.base64_variants.ORIGINAL)
    return {
      publicKey,
      privateKey,
      publicKeyB64: parsed.publicKey,
      identityKeyPair: { publicKey, privateKey },
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
    identityKeyPair: { publicKey: kp.publicKey, privateKey: kp.privateKey },
  }
}

export function clearKeypair(username) {
  localStorage.removeItem(storageKey(username))
  localStorage.removeItem(`signal:${username}:prekeys`)
}
