import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
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
