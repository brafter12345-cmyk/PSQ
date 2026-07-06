import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Base path is driven by SME_BASE_PATH so the same source builds for the VM
// sub-path mount and for local/root serving — mirrors the scanner's
// SCANNER_BASE_PATH=/scanner. For the VM:  SME_BASE_PATH=/smerating/ npm run build
// (PowerShell:  $env:SME_BASE_PATH='/smerating/'; npm run build). Default '/'.
const base = process.env.SME_BASE_PATH || '/';

export default defineConfig({
  base,
  plugins: [react()],
  build: {
    // Flask serves this build; keep it self-contained under the base path.
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: { port: 5173 },
});
