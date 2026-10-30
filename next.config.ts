import type { NextConfig } from "next";

const config: NextConfig = {
  // deploy.sh (loki scripts/hetzner) ships .next/standalone and refuses a build without it.
  output: "standalone",
  poweredByHeader: false,
  async rewrites() {
    return [{ source: "/.well-known/:name", destination: "/api/well-known/:name" }];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "X-Content-Type-Options", value: "nosniff" },
        ],
      },
    ];
  },
};

export default config;
