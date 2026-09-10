import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

/**
 * Read the local control token server-side, from the running Sister's config
 * directory. The browser never receives or persists this token: the Vite dev
 * proxy attaches the Authorization header to upstream requests.
 */
function localControlToken(): string | undefined {
  const dir = process.env.MISAKA_CONFIG_DIR || join(homedir(), ".misaka");
  try {
    const token = readFileSync(join(dir, "local-control-token"), "utf8").trim();
    return token.length > 0 ? token : undefined;
  } catch {
    return undefined;
  }
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "VITE_");
  const token = localControlToken();
  if (!token) {
    console.warn(
      "[misaka] no local-control-token found (set MISAKA_CONFIG_DIR to the " +
        "running Sister's config directory); /api requests will be rejected " +
        "with 401 until a token is present.",
    );
  }
  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        "/api": {
          target: env.VITE_MISAKA_API_URL || "http://127.0.0.1:31702",
          changeOrigin: false,
          // Server-side header injection: the raw control token stays out of
          // browser JS. Do not weaken the API to keep the console working.
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        },
      },
    },
  };
});
