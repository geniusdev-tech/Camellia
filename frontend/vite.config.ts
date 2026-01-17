import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
    plugins: [react()],
    server: {
        port: 3000,
        proxy: {
            '/api': {
                target: 'http://localhost:5000',
                changeOrigin: true,
                secure: false
            }
        }
    },
    build: {
        outDir: '../static/dist',
        emptyOutDir: true,
        sourcemap: false,
        rollupOptions: {
            output: {
                manualChunks: {
                    vendor: ['react', 'react-dom', 'react-router-dom'],
                    query: ['@tanstack/react-query'],
                    ui: ['framer-motion', 'lucide-react']
                }
            }
        }
    },
    resolve: {
        alias: {
            '@': path.resolve(__dirname, './src')
        }
    }
})
