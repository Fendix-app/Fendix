# Fendix GitHub App

> **Status:** end-to-end. The scaffold (webhook server, App-as-bot
> authentication, event router) shipped in v0.6.1 (TASK-107). The
> business logic (clone repo → run scan → post PR comment → upload
> SARIF + check_run re-run) shipped in TASK-107b on top of the
> scaffold. This page documents both the setup steps and the
> deployment recipes.

## What this gives you

A long-running HTTP server that you deploy once per GitHub
account/org. After install:

- Every pull request to a covered repo triggers a webhook to the
  server.
- The server authenticates as the App, mints an installation token,
  and (after TASK-107b lands) clones the PR head, runs `fendix scan`
  in hybrid mode, posts a single PR comment with the findings, and
  uploads the SARIF to the Code Scanning tab so each finding shows up
  inline as a PR annotation.

This is the **zero-config** path for teams that don't want to manage a
`.github/workflows/fendix.yml` themselves. (For self-hosted-CI teams,
`fendix init` writes a Fendix-aware GitHub Actions workflow into the
repo — see [cli-reference](../README.md).)

## Setup

### 1. Create the GitHub App

The fastest path is GitHub's "Create from manifest" flow, which uses
[`app/manifest.yml`](../app/manifest.yml) to pre-populate the App's
permissions and webhook events:

1. Go to one of:
   - **User account:** `https://github.com/settings/apps/new?manifest=...`
   - **Org:** `https://github.com/organizations/<ORG>/settings/apps/new?manifest=...`
2. Paste the manifest YAML (from `app/manifest.yml`) into the
   "Manifest" field.
3. Approve the permissions:
   - **Contents: Read** (clone source for white-box analysis)
   - **Pull requests: Write** (post the findings comment)
   - **Checks: Write** (publish the gating check-run)
   - **Security events: Write** (upload SARIF to Code Scanning)
   - **Metadata: Read** (implicit on every App)
4. Confirm the events: `pull_request`, `push`, `check_run`.
5. Once GitHub creates the App, **download the private key** (it's a
   one-time download — save it; you cannot re-download).

### 2. Install the App on your repos

After creation, GitHub redirects to the App's settings page. Click
**Install App** → pick the account → choose "All repositories" or a
specific subset.

You can also distribute an install URL like
`https://github.com/apps/fendix/installations/new` to teammates.

### 3. Configure the webhook server

`fendix-app` is the webhook handler binary, separate from the
`fendix` CLI. It expects four environment variables:

| Variable | Purpose |
|---|---|
| `FENDIX_APP_ID` | Numeric App ID from the App's settings page (e.g. `1234567`). |
| `FENDIX_APP_PRIVATE_KEY` *or* `FENDIX_APP_PRIVATE_KEY_FILE` | The PEM contents (or path to the PEM file) of the private key downloaded in step 1. |
| `FENDIX_WEBHOOK_SECRET` | The webhook shared secret you configured during App creation. Used to verify `X-Hub-Signature-256` on every incoming request. |
| `FENDIX_LISTEN_ADDR` | Optional. HTTP listen address. Default `:8080`. |
| `FENDIX_GITHUB_API_URL` | Optional. Override for GitHub Enterprise Server. Default `https://api.github.com`. |

A minimal local run for end-to-end smoke testing:

```bash
export FENDIX_APP_ID=1234567
export FENDIX_APP_PRIVATE_KEY_FILE=$HOME/.config/fendix/app-private-key.pem
export FENDIX_WEBHOOK_SECRET=$(openssl rand -hex 32)
go run ./cmd/fendix-app
```

(In production, build the binary with `go build -o fendix-app
./cmd/fendix-app/` and run it under a process supervisor —
`systemd`, `docker run`, a Kubernetes Deployment, etc.)

### 4. Point the App at your deployment

In the App's settings, set the **Webhook URL** to your deployed
server's `/webhook` endpoint (e.g. `https://app.fendix.dev/webhook`).
GitHub will send a `ping` event immediately to confirm reachability;
the server logs `webhook ping ack` on success.

## Endpoints

| Path | Method | Purpose |
|---|---|---|
| `/webhook` | POST | GitHub posts every event here. Signature is verified before any payload is parsed. |
| `/healthz` | GET | Liveness probe. Returns the server's version string. |

## Security model

- **HMAC-SHA256 signature verification on every webhook.** The
  shared secret is required; missing or mismatched signatures return
  `401 Unauthorized` with no payload processing. The legacy
  `X-Hub-Signature` (sha1) header is *rejected* — only the modern
  `X-Hub-Signature-256` is accepted.
- **App JWT lifetime: 9 minutes** (GitHub's max is 10; we leave a
  1-minute clock-skew buffer). The `iat` claim is dated 60 seconds
  in the past for the same reason.
- **Installation tokens are cached in-process per installation ID**
  with a 30-second pre-expiry refresh window. Concurrent webhook
  bursts for the same installation single-flight to one network
  refresh — no thundering herd.
- **Body size cap: 4 MiB.** Larger payloads return `413 Payload Too
  Large` without ever entering the JSON parser. (GitHub's documented
  max is 25 MB; Fendix's working set is well under 2 MB.)
- **Unknown event types return `200 OK` silently.** GitHub disables
  webhook endpoints that 4xx repeatedly; new event types should not
  knock the App offline.

## What's wired today (v0.6.1)

- ✅ `app/manifest.yml` — registerable via GitHub's manifest flow.
- ✅ `cmd/fendix-app` — server entrypoint with signal-driven graceful
  shutdown, configurable listen addr, healthz endpoint.
- ✅ `internal/ghapp/webhook.go` — HMAC sig verify, body-size cap,
  event router (pull_request, push, check_run, ping).
- ✅ `internal/ghapp/auth.go` — pure-stdlib RS256 App-JWT signing,
  `/app/installations/{id}/access_tokens` exchange, single-flight
  token cache via `TokenSource`.
- ✅ Tests: 28 unit tests with `-race`, covering sig verify variants
  (legacy sha1 rejected, tampered body, missing/malformed headers),
  PKCS1 + PKCS8 private-key formats, JWT structural correctness,
  token cache reuse + concurrent single-flight + per-installation
  isolation.

## What's wired today (TASK-107b)

- ✅ PR-event handler **clones the head SHA** via shallow init+fetch
  (only the exact commit, no history). Auth uses the installation
  token as `x-access-token` userinfo on the HTTPS clone URL.
- ✅ Runs `fendix scan --code <tmp> --format json` against the cloned
  source (white-box only — deploy-preview URL discovery is a
  follow-up; not all PRs have one).
- ✅ Renders a Markdown PR comment from the findings JSON. The
  template matches `examples/github-actions/fendix-scan.yml`'s
  github-script step (TASK-098) byte-for-byte modulo whitespace, so
  users see the same output whether they install the App or copy the
  reference workflow.
- ✅ Re-renders SARIF from the same JSON via `fendix report
  --format sarif` and uploads it via the [Code Scanning Upload
  API](https://docs.github.com/en/rest/code-scanning/code-scanning?apiVersion=2022-11-28#upload-an-analysis-as-sarif-data)
  (gzip+base64 encoded, against `refs/pull/<n>/head`). SARIF upload
  is best-effort: a misconfigured repo (Code Scanning disabled) logs
  a warning but the comment still posts.
- ✅ `check_run.action == "rerequested"` re-runs the scan against the
  recorded head SHA. Other check_run actions are silent ack.

## Deployment recipes

### Docker

A multi-stage [`Dockerfile.app`](../Dockerfile.app) lives at the repo root. The
official public image bundles `fendix-app`, the `fendix` CLI, the embedded
Python engine, and `git` (required for the clone step). Pull the verified
multi-platform manifest by digest:

```bash
FENDIX_APP_IMAGE='docker.io/fendixapp/fendix-app@sha256:cdd0fabae6e80abbc3724628e876680f630f2005d378fd47b19265c86fd24d46'
docker pull "$FENDIX_APP_IMAGE"

docker run --rm -p 8080:8080 \
  -e FENDIX_APP_ID=1234567 \
  -e FENDIX_APP_PRIVATE_KEY="$(cat private-key.pem)" \
  -e FENDIX_WEBHOOK_SECRET="$WEBHOOK_SECRET" \
  "$FENDIX_APP_IMAGE"
```

The human-readable version is `3.4.1`; the digest pin prevents a mutable tag
from changing deployed bytes. For local development, use
`docker build -f Dockerfile.app -t fendix-app:local .`.

Image size is dominated by the Python engine + `git` + Debian base
(~250 MiB). For self-hosted runners that already have these on the
host, building `fendix-app` directly with `go build` and running it
under `systemd` is a smaller-footprint alternative.

### Kubernetes

A reference Deployment + Service + Ingress lives at
[`deploy/k8s/fendix-app.yaml`](../deploy/k8s/fendix-app.yaml). It is a starting
template, not a paved-road production manifest. Its official image is already
pinned to the verified `3.4.1` digest; adjust replicas, ingress class/host, and
the TLS secret to your cluster's conventions. Highlights:

- 2 replicas behind a `ClusterIP` Service. Webhook idempotency comes
  from the `X-GitHub-Delivery` UUID — duplicate scans waste a cycle
  but never destroy state.
- `readOnlyRootFilesystem: true` with an `emptyDir` mount at `/tmp`
  for per-scan clone targets.
- Private key wired as a `Secret` mounted at
  `/var/secrets/fendix/private-key.pem` (referenced via
  `FENDIX_APP_PRIVATE_KEY_FILE`).
- App ID + webhook secret wired as a `Secret` consumed via `envFrom`.
- Liveness + readiness probes against `/healthz`.
- 30s `terminationGracePeriodSeconds` so in-flight scans finish
  during a rolling update.

Bootstrap with the `kubectl create secret` commands inlined at the
top of the manifest, then `kubectl apply -f
deploy/k8s/fendix-app.yaml`.

### App engine alternatives

`fendix-app` is a stateless HTTP server with no in-memory dependencies
beyond the in-process token cache. It runs unchanged on:

- Fly.io (`fly launch` from a Dockerfile)
- Cloud Run (with `--min-instances=1` to avoid cold-start webhook
  retries; webhook bodies are size-capped at 4 MiB which fits within
  Cloud Run's 32 MiB limit)
- Render, Railway, etc.

Pick whatever your team already deploys long-running web services on.

## Marketplace listing

Listing the App on the [GitHub
Marketplace](https://github.com/marketplace) is an operator step
distinct from creating the App: it requires the App to be public, an
agreement to the Marketplace developer terms, a per-listing review
from GitHub, and screenshots/copy in the listing form. This is not
codeable and isn't part of TASK-107's scaffold deliverable. Once a
deployment is reachable end-to-end (post-TASK-107b), the Marketplace
listing is a one-off operator submission.

## Troubleshooting

**Webhook 401s on every request.** Double-check the
`FENDIX_WEBHOOK_SECRET` matches the value you set during App
creation. Re-generating the secret in the App's settings invalidates
the old value immediately.

**`unauthorized: 401: Bad credentials` on installation-token
fetch.** The App JWT is being rejected — usually means the wrong
private key is loaded (mismatched key vs the App ID), the system
clock is significantly skewed, or the key file isn't valid PEM.
`openssl rsa -in private-key.pem -check` confirms the PEM parses.

**Events arrive but the PR has no comment.** Filter the logs for
`scan complete`: if it's missing, the scan failed before completing
(network, repo size, SARIF re-render). If it's present but
`PR comment posted` is missing, the App lacks `pull_requests: write`
permission — re-install with the updated permission set. Re-running
"Re-run check" from the Files Changed tab triggers a fresh scan
against the same head SHA without needing a new push.

**SARIF tab stays empty even though the PR comment posted.** The
SARIF upload is best-effort and logs `SARIF upload failed` on a
warning level. Common causes: Code Scanning isn't enabled on the
repo (Settings → Code security and analysis), or the App lacks
`security_events: write`. The comment posts regardless so the user
still sees the findings.

**`webhook signature does not match` on real GitHub events.**
GitHub computes the HMAC over the *raw* request body, including
trailing whitespace. If you have a proxy in front of `fendix-app`
that re-serializes the JSON body (some API gateways do), the
signature will mismatch. Fix: configure the proxy to forward bytes
unchanged.
