import { useEffect, useState, useRef } from 'react';

export const useWebSocket = (url = 'ws://localhost:8000/ws/events') => {
    const [isConnected, setIsConnected] = useState(false);
    const [messages, setMessages] = useState([]);
    const ws = useRef(null);

    useEffect(() => {
        ws.current = new WebSocket(url);

        ws.current.onopen = () => setIsConnected(true);
        ws.current.onclose = () => setIsConnected(false);
        ws.current.onmessage = (event) => {
            const data = JSON.parse(event.data);
            setMessages((prev) => [...prev, data]);
        };

        return () => {
            ws.current?.close();
        };
    }, [url]);

    return { isConnected, messages };
};