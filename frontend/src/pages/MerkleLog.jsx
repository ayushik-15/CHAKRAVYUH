import { Database } from 'lucide-react';

export default function MerkleLog() {
    return (
        <div className="space-y-6">
            <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                <Database className="w-6 h-6 text-primary" />
                Transparency Log
            </h2>
            <div className="bg-surface border border-gray-800 rounded-xl overflow-hidden">
                <table className="w-full text-left text-sm">
                    <thead className="bg-black/50 text-gray-400">
                        <tr>
                            <th className="p-4 font-medium">Timestamp</th>
                            <th className="p-4 font-medium">Event Phase</th>
                            <th className="p-4 font-medium">Cryptographic Hash</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                        <tr className="hover:bg-gray-800/50 transition-colors">
                            <td className="p-4 text-gray-500">Just now</td>
                            <td className="p-4 text-gray-300">System Initialized</td>
                            <td className="p-4 font-mono text-primary text-xs">Awaiting Arbiter STH...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    );
}