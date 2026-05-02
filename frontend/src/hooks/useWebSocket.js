import { useEffect, useRef, useState } from 'react'

export default function useWebSocket(url) {
  const ws = useRef(null)
  const [messages, setMessages] = useState([])
  const [connected, setConnected] = useState(false)

  useEffect(() => {
    const connect = () => {
      ws.current = new WebSocket(url)

      ws.current.onopen = () => setConnected(true)

      ws.current.onmessage = (e) => {
        const data = JSON.parse(e.data)
        setMessages(prev => [...prev, data])
      }

      ws.current.onclose = () => {
        setConnected(false)
        setTimeout(connect, 2000)
      }

      ws.current.onerror = () => {
        ws.current.close()
      }
    }

    connect()
    return () => ws.current?.close()
  }, [url])

  return { messages, connected }
}