import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // Self-contained server bundle for the Docker runtime stage.
  output: "standalone",
  // Same-origin API proxy: lets the browser call relative `/api/...` and
  // `/health`, which the Next server forwards to the co-located backend
  // (all-in-one container, single-port platforms, and local `npm run dev`).
  // Cross-origin deployments set NEXT_PUBLIC_API_URL and bypass these.
  async rewrites() {
    const api = process.env.API_PROXY_TARGET ?? "http://127.0.0.1:8000";
    return [
      { source: "/api/:path*", destination: `${api}/api/:path*` },
      { source: "/health", destination: `${api}/health` },
    ];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=()",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
