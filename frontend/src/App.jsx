import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import { Activity, Shield, Database, LayoutDashboard } from 'lucide-react';
import { useWebSocket } from './services/websocket';
import Dashboard from './pages/Dashboard';
import MerkleLog from './pages/MerkleLog';

function App() {
  const { isConnected } = useWebSocket();

  return (
    <BrowserRouter>
      <div className="flex h-screen bg-background text-gray-200 font-sans">
        {/* Sidebar */}
        <div className="w-64 bg-surface border-r border-gray-800 flex flex-col">
          <div className="p-6 flex items-center gap-3 border-b border-gray-800">
            <Shield className="text-primary w-8 h-8" />
            <h1 className="text-xl font-bold tracking-wider text-white">CHAKRAVYUH</h1>
          </div>
          <nav className="flex-1 p-4 space-y-2">
            <Link to="/" className="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-800 transition-colors text-gray-300 hover:text-primary">
              <LayoutDashboard className="w-5 h-5" />
              Dashboard
            </Link>
            <Link to="/merkle" className="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-800 transition-colors text-gray-300 hover:text-primary">
              <Database className="w-5 h-5" />
              Merkle Log
            </Link>
          </nav>
        </div>

        {/* Main Content */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Header */}
          <header className="h-16 bg-surface border-b border-gray-800 flex items-center justify-between px-6">
            <h2 className="text-lg font-semibold text-white">Evaluation Protocol</h2>
            <div className="flex items-center gap-2 px-4 py-1.5 rounded-full bg-black/50 border border-gray-800">
              <Activity className="w-4 h-4 text-gray-400" />
              <span className="text-sm font-medium text-gray-400">Arbiter Hub:</span>
              <div className={`w-2.5 h-2.5 rounded-full ${isConnected ? 'bg-primary shadow-[0_0_8px_#00ff9d]' : 'bg-danger shadow-[0_0_8px_#ff003c]'}`} />
              <span className="text-xs text-gray-500 ml-1">{isConnected ? 'Connected' : 'Disconnected'}</span>
            </div>
          </header>

          {/* Routing Area */}
          <main className="flex-1 overflow-auto p-6">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/merkle" element={<MerkleLog />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  );
}

export default App;