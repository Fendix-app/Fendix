# Operator Rollout Checklist

> **Historical, non-authoritative checklist.** This document records the
> v0.11 GitHub App rollout plan and must not be used to launch the current
> v3.5.0 product. ADR-010 authorizes contracts/conformance only; the managed
> runtime remains not ready for deployment. Preserve the versioned steps below
> as history.

> Step-by-step guide to take Fendix from "engine shipped" to "live on GitHub Marketplace."
> Steps are sequential (each builds on the prior). Estimated total: ~1 hour of operator time.

---

## Prerequisites

- [ ] `gh` CLI authenticated (`gh auth status`)
- [ ] `fly` CLI authenticated (`fly auth login`) — or substitute your preferred platform
- [ ] Repo is public on GitHub (required for Marketplace)
- [ ] v0.11.0 release artifacts built successfully (`gh run list -w release.yml | head -2` shows the v0.11.0 run as `completed success`)
- [ ] Accuracy scorecard verified locally — `make build && python3 scripts/accuracy/run.py --python-engine` should report `OVERALL  1.000  1.000  1.000` (P/R/F1; v0.27 fixed the v0.26-disclosed SSRF FN). A value below the CI floor (F1 < 0.99) means a regression and submission should wait; [BENCHMARKS.md](../BENCHMARKS.md) is canonical.

---

## Step 1: Register the GitHub App

**Option A — Manual creation (recommended for customization):**

1. Go to https://github.com/settings/apps/new (or `/organizations/<ORG>/settings/apps/new`)
2. Fill in the fields using [`app/manifest.yml`](../app/manifest.yml) as reference:
   - Name: `Fendix`
   - Homepage URL: `https://get.fendix.dev/`
   - Webhook URL: leave blank for now (set after deploy in Step 3)
   - Webhook Secret: generate with `openssl rand -hex 32` — save it
3. Set permissions: Contents (Read), Pull requests (Write), Checks (Write), Security events (Write)
4. Subscribe to events: `pull_request`, `push`, `check_run`
5. Click "Create GitHub App"
6. **Download the private key** (one-time download) → save to `~/.config/fendix/app-private-key.pem`
7. Note the **App ID** from the App's General settings page

**Option B — Manifest flow (one-click, less common):**

POST the JSON-converted manifest to `https://github.com/settings/apps/new` via the
[manifest creation API](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest).
This is programmatic and pre-fills everything, but requires a redirect URL handler.

**Result:** You have `APP_ID`, `private-key.pem`, and `WEBHOOK_SECRET`.

---

## Step 2: Deploy fendix-app

### Option A: Fly.io (recommended for simplicity)

```bash
./scripts/deploy-app.sh
```

The script handles `fly launch` + secrets + deploy. Final output gives you the webhook URL.

### Option B: Docker on any VPS

```bash
docker build -f Dockerfile.app -t fendix-app .
docker run -d --restart=always -p 8080:8080 \
  -e FENDIX_APP_ID=<id> \
  -e FENDIX_APP_PRIVATE_KEY="$(cat private-key.pem)" \
  -e FENDIX_WEBHOOK_SECRET=<secret> \
  --name fendix-app \
  fendix-app
```

Put an HTTPS reverse proxy (caddy, nginx, cloudflare tunnel) in front.

### Option C: Kubernetes

```bash
kubectl create secret generic fendix-app-secrets \
  --from-literal=FENDIX_APP_ID=<id> \
  --from-literal=FENDIX_WEBHOOK_SECRET=<secret> \
  --from-file=private-key.pem=./private-key.pem

kubectl apply -f deploy/k8s/fendix-app.yaml
```

---

## Step 3: Point the App at your deployment

1. Go to App settings → Webhook URL
2. Set to `https://<your-host>/webhook`
3. GitHub sends a `ping` event → verify in logs (`fly logs` or `kubectl logs`)

---

## Step 4: Install the App on test repos

1. App settings → Install App → pick your account
2. Choose a test repo (or "All repositories")
3. Open a PR → verify Fendix comment appears within ~60s

---

## Step 5: Submit Marketplace listing

1. App settings → "List on Marketplace"
2. Use copy from [`docs/marketplace-listing.md`](marketplace-listing.md)
3. Upload screenshots (run `fendix demo --open` to generate them)
4. Pricing: Free
5. Submit for GitHub review (typically 1-3 business days)

---

## Step 6: Seed community issues

```bash
./scripts/seed-issues.sh
```

Creates 5 `good first issue` tickets (3 Semgrep rules, 1 docs, 1 plugin).

---

## Step 7: Publish launch post

Draft in [`docs/launch-post.md`](launch-post.md). Three versions:
- HN (Show HN format, technical depth)
- r/devops (outcome-focused)
- r/golang (architecture-focused)

**Timing:** Post after the Marketplace listing is approved (shows "Install" button works).

**Headline angle:** Lead with the F1 = 1.000 labeled-corpus result (reproduced + CI-gated; v0.26's disclosed SSRF FN fixed in v0.27) and the "6.1 ms cold start, no Python required" cold-start number — those are the two concrete, falsifiable claims that distinguish fendix from the field. Quote the canonical, reproducible numbers from [BENCHMARKS.md](../BENCHMARKS.md). Avoid "fast" and "accurate" as standalone adjectives; numbers do the work.

---

## Step 8: Verify end-to-end

- [ ] `curl https://<host>/healthz` returns version string
- [ ] PR on a test repo gets a Fendix comment within 60s
- [ ] SARIF annotations appear in Code Scanning tab
- [ ] "Re-run" button on the check works
- [ ] Marketplace listing shows "Install" and permissions are correct
- [ ] `good first issue` labels visible on the Issues tab
- [ ] README links resolve (get.fendix.dev, ADR-007, docs/plugins.md)

---

## Rollback

If something goes wrong:
- **App producing bad comments:** `fly scale count 0` (or scale k8s to 0 replicas)
- **Webhook errors:** Check `gh api /app/hook/deliveries` for failed deliveries
- **Need to regenerate secrets:** Update in App settings + `fly secrets set ...`
