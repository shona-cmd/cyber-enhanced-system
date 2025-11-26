import { useAuth } from './context/AuthContext';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import AppRouter from './routes/AppRouter';
import MTACLogin from './MTACLogin';

export default function App() {
  const { user } = useAuth();

  return <MTACLogin />;
}
