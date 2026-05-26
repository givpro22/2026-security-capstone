// Minimal WebSocket wrapper. The token is passed as a query param because
// browsers do not let us set Authorization headers on WS handshake.

export function connectSocket(token, handlers) {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  const url = `${proto}://${window.location.host}/ws?token=${encodeURIComponent(token)}`
  const ws = new WebSocket(url)

  ws.onopen = () => handlers.onOpen?.()
  ws.onclose = (e) => handlers.onClose?.(e)
  ws.onerror = (e) => handlers.onError?.(e)
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data)
      handlers.onMessage?.(data)
    } catch (err) {
      console.error('bad ws payload', err)
    }
  }

  return {
    send(payload) {
      if (ws.readyState !== WebSocket.OPEN) {
        throw new Error('socket not open')
      }
      ws.send(JSON.stringify(payload))
    },
    close() {
      ws.close()
    },
    get readyState() {
      return ws.readyState
    },
  }
}
