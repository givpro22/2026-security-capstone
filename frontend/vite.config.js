import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
import { resolve, dirname } from 'node:path'

const __dirname = dirname(fileURLToPath(import.meta.url))

// libsodium-wrappers 0.7.16 ships a broken ESM build whose .mjs imports a
// sibling ./libsodium.mjs that does not exist in that folder. The CJS build
// works, but the package's `exports` field blocks deep subpath imports, so we
// alias to the absolute file path to bypass the exports check entirely.
//
// We use the SUMO build because the default build omits crypto_hash_sha256,
// which Noise XX (Noise_XX_25519_ChaChaPoly_SHA256) needs.
const libsodiumCjs = resolve(
  __dirname,
  'node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js',
)

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      'libsodium-wrappers': libsodiumCjs,
    },
  },
  optimizeDeps: {
    include: ['libsodium-wrappers'],
  },
  server: {
    port: 5173,
    proxy: {
      '/auth': 'http://localhost:8000',
      '/keys': 'http://localhost:8000',
      '/ws': { target: 'ws://localhost:8000', ws: true },
    },
  },
})
