import type { NextConfig } from "next";

const isProd = process.env.NODE_ENV === "production";
// During `next dev`, proxy API calls to a running agent (default demo port).
const agent = process.env.AGENT_URL || "http://127.0.0.1:8787";

const nextConfig: NextConfig = {
  // create-next-app also enables `cacheComponents` and `partialPrefetching`, but
  // both need a Node server (PPR) and are rejected by `output: "export"`, so they
  // are left off: myOwl ships the UI as static files inside the Go binary.
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  // myOwl: the production build is a static export embedded into the Go binary.
  reactStrictMode: true,
  images: { unoptimized: true },
  trailingSlash: false,
  ...(isProd
    ? { output: "export" as const }
    : {
        async rewrites() {
          return [{ source: "/api/:path*", destination: `${agent}/api/:path*` }];
        },
      }),
};

export default nextConfig;
