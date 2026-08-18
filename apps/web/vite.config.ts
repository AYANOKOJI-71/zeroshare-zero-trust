import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    allowedHosts: ['localhost', '5175-iqzvoujaz6wicttdu1y4u-6cb4feab.us4.manus.computer'],
    proxy: { '/api': { target: process.env.VITE_API_ORIGIN ?? 'http://127.0.0.1:4000', changeOrigin: true } }
  }
})
