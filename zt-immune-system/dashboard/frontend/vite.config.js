import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path'; // Import the 'path' module

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000, // Optional: specify a port for the dev server
    open: true, // Optional: automatically open in browser
  },
  build: {
    outDir: 'build', // Optional: specify output directory, default is 'dist'
  }
});
