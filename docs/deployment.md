# Deployment

DL Sentinel's server is a single Node ≥ 20 process that serves both the HTTP API and the
dashboard. It has no database (JSON persistence under a data directory) and no required
network access, so it deploys anywhere Node runs. What it is **not** is a static site: the
scanner and API need a running process and a writable disk, so pure static/"dist" hosting
(GitHub Pages, Netlify static, …) cannot host the product itself — though it can host
generated reports (see below).

## Bare Node (any Linux box, VPS, home server)

```bash
git clone https://github.com/Dhiva-Labs/dl-sentinel.git
cd dl-sentinel
npm ci
npm run build

SENTINEL_API_TOKEN=change-me \
SENTINEL_SCAN_ROOT=/srv/repos \
SENTINEL_DATA_DIR=/var/lib/dl-sentinel \
node apps/api/dist/main.js
```

The dashboard is served at `http://host:8752/`; paste the token in its Settings page.

A minimal systemd unit:

```ini
[Unit]
Description=DL Sentinel
After=network.target

[Service]
User=sentinel
WorkingDirectory=/opt/dl-sentinel
Environment=SENTINEL_API_TOKEN=change-me
Environment=SENTINEL_SCAN_ROOT=/srv/repos
Environment=SENTINEL_DATA_DIR=/var/lib/dl-sentinel
ExecStart=/usr/bin/node apps/api/dist/main.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Docker / Compose

A `Dockerfile` and `compose.yaml` ship at the repository root:

```bash
SENTINEL_API_TOKEN=change-me docker compose up -d
```

Mount every directory you want scannable read-only under `/scans` (edit the `volumes:` list),
and keep the named `sentinel-data` volume for persistence. The image runs as the non-root
`node` user, pins its base tag, and passes DL Sentinel's own infra scanner. These files are
authored and scanner-verified in CI-less fashion — build the image on a Docker-capable host.

## Environment reference

| Variable | Default | Meaning |
| --- | --- | --- |
| `SENTINEL_API_TOKEN` | generated + printed | Root admin bearer token |
| `PORT` | `8752` | Listen port |
| `SENTINEL_SCAN_ROOT` | process cwd | Only paths inside this root may be scanned |
| `SENTINEL_DATA_DIR` | `.dl-sentinel/` | Reports, schedules, users, audit log |
| `SENTINEL_SCAN_CONCURRENCY` | `2` | Parallel scan workers |
| `SENTINEL_RATE_LIMIT_MAX` / `_WINDOW_MS` | `60` / `60000` | API rate limit |
| `SENTINEL_MAX_BODY_BYTES` | `1048576` | Request body cap |

## Exposing it beyond localhost

The server speaks plain HTTP. If you expose it outside a trusted network, terminate TLS in
front of it (Caddy, nginx, a cloud load balancer) and keep the bearer token secret:

```text
caddyfile:  sentinel.example.com { reverse_proxy 127.0.0.1:8752 }
```

The API sends no CORS headers by design — the dashboard is same-origin, served by the API
itself. Keep them on one origin.

## Static hosting: publish reports, not the app

For a zero-server read-only view, render reports in CI and publish those artifacts to any
static host:

```bash
sentinel scan . --format markdown --output public/security-report.md
sentinel scan . --format sarif    --output public/security.sarif
```

Pair with the GitHub Action (`apps/action`) for PR-time scanning — see its README.
