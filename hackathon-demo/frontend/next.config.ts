import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  webpack: (config, { isServer }) => {
    if (!isServer) {
      // snarkjs uses Node.js built-ins; tell webpack to stub them in the browser
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        path: false,
        crypto: false,
        os: false,
        stream: false,
        readline: false,
        worker_threads: false,
      };
    }
    return config;
  },
  turbopack: {}, // Silence Next.js 16 error regarding custom webpack config
};

export default nextConfig;
