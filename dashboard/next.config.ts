import type { NextConfig } from "next";

const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-XSS-Protection", value: "0" },
  {
    key: "Referrer-Policy",
    value: "strict-origin-when-cross-origin",
  },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=()",
  },
  {
    key: "Content-Security-Policy",
    value:
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
  },
];

const noCacheHeader = {
  key: "Cache-Control",
  value: "no-store, no-cache, must-revalidate",
};

const nextConfig: NextConfig = {
  output: "standalone",
  headers: async () => [
    {
      source: "/:path*",
      headers: securityHeaders,
    },
    {
      source: "/api/:path*",
      headers: [noCacheHeader],
    },
    {
      source: "/login",
      headers: [noCacheHeader],
    },
    {
      source: "/setup",
      headers: [noCacheHeader],
    },
  ],
};

export default nextConfig;
