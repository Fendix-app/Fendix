# Fendix — GitLab CI next steps

`fendix init --ci gitlab` wrote `.gitlab-ci.fendix.yml` to your repo
root. GitLab CI doesn't merge multiple files in `.gitlab-ci.yml`
locations automatically; you wire the snippet in by adding an
`include:` line to your main `.gitlab-ci.yml`:

```yaml
include:
  - local: .gitlab-ci.fendix.yml
```

If you don't have a `.gitlab-ci.yml` yet, create one containing just
the `include:` block above (plus a `stages:` line that lists `test`).

## Pinning the Fendix version

`fendix init` pins `FENDIX_VERSION` in `.gitlab-ci.fendix.yml` to the
Fendix release that generated it, so every pipeline installs the same
verified binary. To upgrade, change it to a newer tag from
<https://github.com/Fendix-app/Fendix/releases>:

```yaml
variables:
  FENDIX_VERSION: "vX.Y.Z"
```

The install step rejects anything that is not a release tag, including
"latest".

## Required project settings

- **GitLab SAST report ingestion** — Premium / Ultimate tiers expose
  the SAST report under `Security & Compliance → Vulnerability
  Report`. Free tier still receives the JSON as a job artifact at
  `gl-sast-report.json`.
- **No tokens needed for the public install path.** If your scan
  target requires credentials, plumb them via masked CI variables
  and reference them in the `script:` block.

## Commit

```bash
git add .gitlab-ci.fendix.yml
git commit -m "Add Fendix security scanning"
```
