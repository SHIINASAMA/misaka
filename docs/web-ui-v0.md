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

The console uses read-only network views and the side-effect-free `Ping Sister`
action. The backend API also exposes `POST /api/v1/jobs` for the CLI to submit
commands through the running Sister; the console does not currently provide a
job-submission screen. The API does not expose keys, membership material,
authorization tokens, file operations, SSH, tunnels, or settings mutation.

The API is authenticated with the machine-local **local control token**: every
`/api/v1/*` route requires `Authorization: Bearer <token>`, and the Vite dev
proxy reads `MISAKA_CONFIG_DIR/local-control-token` **server-side** and injects
the header. The browser never receives or persists the token, and the API is
never weakened to keep the console working. A single unauthenticated
`GET /healthz` returns `{"status":"ok"}` for liveness; there is no browser
login, OAuth, cookies, or session management in v1.

The API remains loopback-only, and it executes local jobs as the daemon's OS
user / signs remote jobs with its local Human material. The control token
protects against other local users/processes that cannot read the owner's
config files; it does not defend against same-user malware. Do not publish the
API through a proxy. See [deployment-v1.md](deployment-v1.md) for the token and
threat model, and [human-authorization-v0.md](human-authorization-v0.md) for
the execution and authorization boundaries.

## Build the frontend

```bash
cd web
npm run typecheck
npm run build
```

The build output stays in `web/dist/` and is not consumed by the Rust binary. Public hosting, browser authentication, LAN API access, and static asset integration are future work.
