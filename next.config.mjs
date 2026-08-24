/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // Enables src/instrumentation.ts's register() hook, used to start the auto-sync
  // scheduler once when the server process boots. Stable by default from Next.js 15;
  // this project is on 14.2.x, where it still needs the explicit opt-in.
  experimental: {
    instrumentationHook: true,
  },
};

export default nextConfig;
