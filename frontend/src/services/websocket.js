import { useEffect, useState, useRef } from 'react';

export const useWebSocket = (url = 'wss://[chakravyuh-arbiter.onrender.com/ws/events](https://chakravyuh-arbiter.onrender.com/ws/events)') => {
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