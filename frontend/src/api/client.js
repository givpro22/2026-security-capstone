// Thin wrapper over fetch. Adds the bearer token if we have one.

let _token = null

export function setToken(token) {
  _token = token
  if (token) {
    localStorage.setItem('e2ee-chat:token', token)
  } else {
    localStorage.removeItem('e2ee-chat:token')
  }
}

export function loadToken() {
  _token = localStorage.getItem('e2ee-chat:token')
  return _token
}

export function getToken() {
  return _token
}

async function request(method, path, body) {
  const headers = { 'Content-Type': 'application/json' }
  if (_token) headers['Authorization'] = `Bearer ${_token}`
  const res = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    let detail = res.statusText
    try {
      const j = await res.json()
      detail = j.detail || detail
    } catch {}
    throw new Error(detail)
  }
  if (res.status === 204) return null
  return res.json()
}

export const api = {
  register: (username, password) =>
    request('POST', '/auth/register', { username, password }),
  login: (username, password) =>
    request('POST', '/auth/login', { username, password }),
  me: () => request('GET', '/auth/me'),
  uploadPublicKey: (publicKey) =>
    request('POST', '/keys/me', { public_key: publicKey }),
  getPublicKey: (username) => request('GET', `/keys/${username}`),
  listUsers: () => request('GET', '/keys'),
}
