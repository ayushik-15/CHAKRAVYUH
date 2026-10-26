import { useWebSocket } from '../services/websocket';
import { ShieldAlert, ShieldCheck } from 'lucide-react';

export default function Dashboard() {
    const { isConnected, messages } = useWebSocket();

    return (
        <div className="space-y-6">
            <h2 className="text-2xl font-bold text-white">Live Evaluation Feed</h2>
            <div className="grid gap-4">
                {messages.length === 0 && (
                    <div className="p-6 bg-surface border border-gray-800 rounded-xl text-gray-400">
                        {isConnected ? 'Listening for Commit-Reveal events...' : 'Waiting for connection...'}
                    </div>
                )}
                {messages.map((msg, i) => (
                    <div key={i} className="p-4 bg-surface border border-gray-800 rounded-xl flex items-start gap-4">
                        {msg.type === 'attack' ? <ShieldAlert className="text-danger w-6 h-6" /> : <ShieldCheck className="text-primary w-6 h-6" />}
                        <div>
                            <h3 className="font-bold text-white">{msg.plane || 'System Event'}</h3>
                            <p className="text-gray-400 text-sm mt-1">{msg.payload || JSON.stringify(msg)}</p>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}