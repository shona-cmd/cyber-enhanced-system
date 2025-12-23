import { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';

export default function Dashboard() {
  const [devices, setDevices] = useState([]);
  const { user, logout } = useAuth();

  useEffect(() => {
    fetch('/api/devices', {
      headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
    })
      .then(r => r.json())
      .then(setDevices);
  }, []);

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <nav className="bg-gray-800 border-b border-cyan-500 p-4">
        <div className="max-w-7xl mx-auto flex justify-between items-center">
          <h1 className="text-2xl font-bold text-cyan-400">NaashonSecureIoT</h1>
          <div className="flex items-center gap-4">
            <span className="text-sm">Logged in as <strong>{user?.username}</strong> ({user?.role})</span>
            <button onClick={logout} className="px-4 py-2 bg-red-600 hover:bg-red-500 rounded">
              Logout
            </button>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto p-8">
        <h2 className="text-4xl font-bold mb-8 text-cyan-400">Live IoT Devices – MTAC Uganda</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {devices.map(d => (
            <div key={d.id} className={`p-6 rounded-xl border ${d.alert ? 'border-red-500 bg-red-900/20' : 'border-cyan-500'} backdrop-blur`}>
              <h3 className="text-xl font-bold">{d.name}</h3>
              <p className="text-3xl mt-4">{typeof d.value === 'number' ? d.value.toFixed(1) : d.value}</p>
              <p className="text-gray-400">{d.location}</p>
              {d.alert && <p className="text-red-400 mt-4 font-bold">⚠ {d.message}</p>}
              <span className={`inline-block mt-4 px-3 py-1 rounded text-sm ${d.status === 'online' ? 'bg-green-600' : 'bg-gray-600'}`}>
                {d.status.toUpperCase()}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
