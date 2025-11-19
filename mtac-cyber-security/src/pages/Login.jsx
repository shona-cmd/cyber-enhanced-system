import { useState } from 'react';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const [username, setUsername] = useState('mtac-admin');
  const [password, setPassword] = useState('Mtac2025!');
  const [error, setError] = useState('');
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    const res = await login(username, password);
    if (res.error) setError(res.error);
  };

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center">
      <div className="bg-gray-800 p-10 rounded-xl shadow-2xl border border-cyan-500">
        <h1 className="text-3xl font-bold text-cyan-400 mb-8 text-center">
          NaashonSecureIoT
        </h1>
        <form onSubmit={handleSubmit} className="space-y-6">
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full px-4 py-3 bg-gray-700 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500"
            placeholder="Username"
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-4 py-3 bg-gray-700 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500"
            placeholder="Password"
          />
          <button
            type="submit"
            className="w-full py-3 bg-cyan-500 hover:bg-cyan-400 text-black font-bold rounded-lg transition"
          >
            LOGIN – MTAC SECURE ACCESS
          </button>
          {error && <p className="text-red-500 text-center">{error}</p>}
        </form>
        <p className="text-gray-400 text-sm mt-6 text-center">
          Demo: mtac-admin / Mtac2025!
        </p>
      </div>
    </div>
  );
}
