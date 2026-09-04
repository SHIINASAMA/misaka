# Misaka Web UI v0 — local development

Misaka is the backend daemon. The Sister Console is a separate Vite application and is not bundled into the `misaka` binary.

## Start the backend

Use an isolated config directory for local experiments:

```bash
MISAKA_CONFIG_DIR=/tmp/misaka-ui-sister \
  cargo run -p misaka -- start \
    --port 31700 \
    --api-port 31702 \
    --discovery off
```

The API listens on `127.0.0.1:31702`. It is deliberately loopback-only in v0 and rejects public/LAN bind addresses.

Check the API directly:

```bash
curl http://127.0.0.1:31702/api/v1/overview
curl http://127.0.0.1:31702/api/v1/sisters
curl http://127.0.0.1:31702/api/v1/streams
```

## Start the frontend

In a second terminal:

```bash
cd web
npm install
npm run dev
```

Open the Vite URL, normally `http://127.0.0.1:5173/`. The Vite server proxies `/api` to the local Misaka API. To use another development API origin, set `VITE_MISAKA_API_URL` before `npm run dev`.

## Available screens

```text
/                  Overview and connection pulse rail
/sisters           Known Sister list
/sisters/:id       Sister identity, resources, routes, and Ping
/connections       Active stream telemetry
/settings          Local API and hosting boundary
```

The v0 API exposes only read-only network views and the side-effect-free `Ping Sister` action. It does not expose keys, membership material, authorization tokens, file operations, SSH, tunnels, or settings mutation.

## Build the frontend

```bash
cd web
npm run typecheck
npm run build
```

The build output stays in `web/dist/` and is not consumed by the Rust binary. Public hosting, browser authentication, LAN API access, and static asset integration are future work.
