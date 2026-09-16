import { defineConfig } from "vite";

export default defineConfig({
  build: {
    outDir: "../assets",
    emptyOutDir: true,
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        assetFileNames: "app.[ext]",
      },
    },
  },
});
