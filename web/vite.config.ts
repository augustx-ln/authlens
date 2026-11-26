import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  base: process.env.GITHUB_ACTIONS ? '/authlens/' : '/',
  server: {
    proxy: { '/api': 'http://127.0.0.1:3000' },
  },
})
