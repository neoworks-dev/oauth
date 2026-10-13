import path from "node:path"
import { svelte } from "@sveltejs/vite-plugin-svelte"
import { defineConfig } from "vite"

const legacyPrefix = "$legacy/"

// The plain modules the views call stay out of the bundle: the keystore holds the unlocked
// account key in module state, so app.js and the views must share one instance of it.
export default defineConfig({
  plugins: [svelte()],
  resolve: {
    alias: { $legacy: path.resolve(import.meta.dirname, "handlers/vault/static") },
  },
  build: {
    outDir: "handlers/vault/static",
    emptyOutDir: false,
    minify: false,
    lib: { entry: "ui/main.js", formats: ["es"], fileName: () => "vault-views.js" },
    rollupOptions: {
      external: (id) => id.startsWith(legacyPrefix),
      output: { paths: (id) => id.replace(legacyPrefix, "./") },
    },
  },
})
