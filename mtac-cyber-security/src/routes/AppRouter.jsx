import React from 'react';
import { BrowserRouter, Routes, Route, Link, Navigate } from 'react-router-dom';
import Dashboard from '../pages/Dashboard.jsx';
import Settings from '../pages/Settings.jsx';
import NotFound from '../pages/NotFound.jsx';
import MTACLogin from '../MTACLogin.jsx';
import { useAuth } from '../context/AuthContext';

function AppRouter() {
  const { token } = useAuth();

  return (
    <BrowserRouter>
      <div>
        <h1>App Router</h1>
        <nav>
          <ul>
            <li>
              <Link to="/">Dashboard</Link>
            </li>
            <li>
              <Link to="/settings">Settings</Link>
            </li>
          </ul>
        </nav>
        <Routes>
          <Route
            path="/"
            element={token ? <Dashboard /> : <Navigate to="/mtac-login" />}
          />
          <Route path="/mtac-login" element={<MTACLogin />} />
          <Route
            path="/settings"
            element={token ? <Settings /> : <Navigate to="/mtac-login" />}
          />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default AppRouter;
