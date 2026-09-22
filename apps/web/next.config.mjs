/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,

  // DEV ONLY. The dev stack bind-mounts the host source tree into the container
  // (infra/docker-compose.override.yml: ../apps/web:/srv). That host path is a
  // Windows/OneDrive directory, and inotify events do not cross that boundary, so
  // webpack's default watcher never fires: editing a component left the browser
  // serving the chunk compiled at container start, with no "Compiling ..." line in
  // the dev log and no error to explain it. Polling is the standard workaround for a
  // bind-mounted source tree.
  //
  // `next build` does not watch files, so this affects the dev server only and cannot
  // change the production bundle.
  webpack: (config, { dev }) => {
    if (dev) {
      config.watchOptions = {
        poll: 1000,
        aggregateTimeout: 300,
        ignored: ["**/node_modules/**", "**/.next/**", "**/.git/**"],
      };
    }
    return config;
  },
};

export default nextConfig;
