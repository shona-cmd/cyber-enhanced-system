import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',      // allows access from other devices on LAN
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'https://localhost:3000',
        changeOrigin: true,
        secure: false,    // accept self-signed cert from backend
        rewrite: (path) => path.replace(/^\/api/, '')
      }
    }
  }
})
