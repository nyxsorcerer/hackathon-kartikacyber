import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.NUMEN_API_PROXY || "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    // ponytail: the default worker count times out 5 s tests and 1 s findBy lookups
    // under load on an 8 GB Docker Desktop; raise it when the test VM grows.
    maxWorkers: 2,
  },
});
