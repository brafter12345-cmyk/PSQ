import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

// The dashboard is mounted INSIDE the Flask app: built assets land in
// security_scanner/static/dashboard and are served by Flask's default
// /static handler. results.html references /static/dashboard/app.{js,css}.
// Stable (non-hashed) entry names keep that template reference fixed.
export default defineConfig(({ command }) => ({
  plugins: [react()],
  // Dev server serves from root; production build is served by Flask under /static.
  // SCANNER_BASE_PATH lets us mount the whole app under a sub-path (e.g. "/scanner")
  // so it can live at https://host/scanner without owning the domain root. Build with
  // `SCANNER_BASE_PATH=/scanner npm run build`; leave it unset for a root deploy.
  base: command === 'build'
    ? `${(process.env.SCANNER_BASE_PATH ?? '').replace(/\/$/, '')}/static/dashboard/`
    : '/',
  build: {
    outDir: fileURLToPath(new URL('../static/dashboard', import.meta.url)),
    emptyOutDir: true,
    rollupOptions: {
      output: {
        entryFileNames: 'app.js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: (info) => {
          const name = (info as { names?: string[]; name?: string }).names?.[0]
            ?? (info as { name?: string }).name ?? ''
          if (name.endsWith('.css')) return 'app.css'
          return 'assets/[name]-[hash][extname]'
        },
      },
    },
  },
  server: { port: 5174, strictPort: false },
}))
