/** @type {import('next').NextConfig} */
const isProd = process.env.NODE_ENV === 'production'
const explicitApiBase = process.env.NEXT_PUBLIC_API_BASE_URL

const nextConfig = {
  // Static export so Tauri can serve files from disk (production)
  ...(isProd ? { output: 'export' } : {}),
  distDir: 'out',
  images: {
    unoptimized: true,
  },
  // Trailing slash ensures each route has its own index.html
  trailingSlash: true,
  // In dev, proxy API requests to Flask
  ...((isProd || explicitApiBase)
    ? {}
    : {
        async rewrites() {
          return [
            {
              source: '/api/:path*',
              destination: 'http://localhost:5000/api/:path*',
            },
          ]
        },
      }),
}

export default nextConfig
