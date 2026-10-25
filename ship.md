# Shipping Fendix — Release Runbook

> Use this every time you cut a new version. Last updated: 2026-09-21
> (reconciled against `.github/workflows/release.yml` after v3.4.1).
>
> Operator-only prerequisites that an agent cannot perform (cosign repo
> variable, DNS, license posture) live in [`RELEASE_RUNBOOK.md`](RELEASE_RUNBOOK.md).

---

## Quick path: tag + push

```bash
# 1. Pick the next version per SemVer
#    - patch (v0.4.2): bug fixes only, no behavior change
#    - minor (v0.5.0): new features, backward-compatible (e.g., Phase 12 ships)
#    - major (v1.0.0): breaking changes (CLI flag rename, JSON schema break)

# 1b. Python lock: the composite Action installs a release's Python engine
#     from python/requirements.lock (hash-locked, --require-hashes). CI fails
#     when requirements.txt changed without a new lock; if it does, regenerate
#     (about 20 minutes; CPython 3.11, linux/amd64, pinned image and
#     pip-tools) and commit the lock before tagging. Never regenerate in CI.
#     sh scripts/release/regenerate-python-lock.sh             # keep pins
#     sh scripts/release/regenerate-python-lock.sh --upgrade   # re-resolve

# 2. Roll the CHANGELOG: rename [Unreleased] → [X.Y.Z] - YYYY-MM-DD,
#    write a 1-paragraph summary, then bullet under ### Added/Changed/Fixed.
#    Keep the empty ## [Unreleased] heading at the top.

# 3. Commit the CHANGELOG roll
git add CHANGELOG.md
git commit -m "chore(release): roll CHANGELOG to vX.Y.Z"
git push origin main

# 4. Annotated tag. The message is the tag annotation only: release.yml
#    publishes with generate_release_notes: true, so the GitHub Release body
#    starts as GitHub's generated notes, not this message. Set the approved
#    body after the workflow finishes (see below).
git tag -a vX.Y.Z -m "vX.Y.Z — short headline

What changed:
- bullet 1
- bullet 2"

# 5. Push tag → triggers release.yml
git push origin vX.Y.Z

# 6. Watch (4 job groups, ~2–3 min total)
gh run watch $(gh run list --workflow=Release --limit 1 --json databaseId --jq '.[0].databaseId')
```

---

## What the workflow does

The pipeline at `.github/workflows/release.yml` runs end-to-end on every `vX.Y.Z` tag (its glob `v[0-9]*.[0-9]*.[0-9]*` also matches pre-release tags such as `v3.5.0-rc.2`; a moving pointer like `v1` does not trigger it) without manual intervention:

| Job | What it does | Output |
|---|---|---|
| `enforce-signing` | Gate: fails the tag unless `vars.COSIGN_ENABLED=true` (or the explicit `allow-unsigned` escape hatch). Runs first; everything else `needs` it | Pass/fail — an unsigned official release cannot happen by accident |
| `release` (×4 matrix) | Cross-compiles for linux/amd64, **linux/arm64**, darwin/amd64, darwin/arm64 (no embedded Python engine since TASK-118 — `make embed-engine` resets the embed dir to a placeholder); builds `.deb` + `.rpm` via nfpm on the linux targets; cosign-signs binaries + packages + SBOMs; emits CycloneDX + SPDX SBOMs and SLSA v1.0 provenance; computes sha256 | Workflow artifacts `fendix-{linux,darwin}-{amd64,arm64}` plus `.deb`/`.rpm`/`.sig`/`.crt`/`.cdx.json`/`.spdx.json`/`.intoto.jsonl` sidecars |
| `publish` | Downloads matrix artifacts, creates the engine-repository GitHub Release with GitHub-generated notes (`generate_release_notes: true`; the tag message is not used) | <https://github.com/Fendix-app/Fendix/releases/tag/vX.Y.Z> |
| `docker` | Gates a multi-architecture candidate, publishes the immutable version to Docker Hub, verifies its clean pull and attestations, then moves convenience tags | `docker.io/fendixapp/fendix:X.Y.Z`, `:X.Y`, `:X`, and `:latest` for stable releases |
| `mirror` | Creates the public mirror release with binaries and checksums, then updates `Formula/fendix.rb` with fresh SHA-256 values | <https://github.com/Fendix-app/homebrew-fendix/releases/tag/vX.Y.Z> |

The public mirror provides the Homebrew tap, installer host, and compatibility
release assets independently of the source repository.

---

## After the workflow finishes

```bash
# Verify (~30 sec)
gh release view vX.Y.Z -R Fendix-app/Fendix
gh release view vX.Y.Z -R Fendix-app/homebrew-fendix
docker pull docker.io/fendixapp/fendix:X.Y.Z  # multi-arch manifest picks the right platform

# Replace the generated Release body with the approved notes, then read it back
gh release edit vX.Y.Z -R Fendix-app/Fendix --notes-file release-notes-vX.Y.Z.txt
gh release view vX.Y.Z -R Fendix-app/Fendix --json body --jq .body | diff - release-notes-vX.Y.Z.txt && echo "release body matches"
```

Optional: spot-check that `brew install fendix` (with the tap added and the formula trusted through `brew trust --formula Fendix-app/fendix/fendix`) picks up the new version.

The install commands in `README.md` are version-agnostic, but several
documents pin the released artifacts and need a follow-up PR once the
release is verified:

- `Formula/fendix.rb`: render it with `scripts/release/render-homebrew-formula.sh`
  from the four binary SHA-256 values; it must equal the formula the
  `mirror` job published to `Fendix-app/homebrew-fendix`.
- The immutable image digest and the `release.yml@refs/tags/vX.Y.Z` identity in
  `README.md`, `SECURITY.md`, `docs/trust-center.md`, `docs/install.md` and the
  `docs/INTEGRATION_GUIDE.md` Docker examples, plus the README digest check in
  `scripts/check-public-claims.sh`. Run each documented `cosign verify` and
  `cosign verify-attestation` command against the new digest before
  committing it.
- The reference workflow (`examples/github-actions/fendix-scan.yml`) and the
  copies of it in the docs move in their own PR, followed by its end-to-end
  run.

---

## Versioning rules of thumb

Fendix is post-1.0 (current release **v3.7.0**), so SemVer applies
at full strength — the pre-1.0 "minor bump = breaking is fine" latitude is gone.

| Bump | When | Examples from history |
|---|---|---|
| Major (`vX.0.0`) | Breaking change to anything users depend on (CLI flag removal/rename, JSON schema break, finding ID format change). The public output shape is frozen and additive-only: `.fendix.yaml` keys, CLI flag names, `models.Finding` JSON field names, SARIF structure, the 0/1/2 exit-code contract. | v1.0.0 = first stable contract |
| Minor (`v1.X.0`) | New features, backward-compatible. New CLI flag, new check type, new output format, new analyzer, new optional JSON field. | v1.1.0 = real-world precision + FP reduction |
| Patch (`v1.X.Y`) | Bug fixes, build/CI/distribution fixes, doc-only changes. No new user-visible features. | v0.4.1 = build infra fixes |

When unsure, prefer the larger bump. Cheap.

---

## Troubleshooting

### `mirror` job failed

- **First check:** is `DIST_REPO_TOKEN` still valid? Fine-grained PATs expire (max 1 year). Renew at github.com → Settings → Developer settings → Personal access tokens → Fine-grained tokens.
- **`Permission to Fendix-app/homebrew-fendix.git denied` (403):** the token cannot write to the org-owned mirror. A fine-grained PAT reaches only repositories of its resource owner, so it must be created with **Fendix-app** as the resource owner and `Contents: Read and write` on `homebrew-fendix`. v3.5.0, the first stable release after the mirror moved to the organization, failed this way; the job stops before the mirror release is created, so `gh run rerun <id> --failed` is safe once the secret is replaced.
- **Logs:** `gh run view <id> --log-failed | grep -A 5 -i "Mirror"`
- **Re-run flow:** if it's a transient failure (rare), re-running just the failed job won't work because the mirror job uses `gh release create` which fails on duplicate tags. Easier to fix-forward: push a new commit to main with the fix, delete the tag, re-tag.

### `docker` job failed

- **Docker build error?** Likely a Dockerfile issue — read the buildx output. Test locally with `docker build .`.
- **Push 401/403?** Check that the workflow has `permissions: packages: write` (it does at workflow level).
- **Image visibility:** new packages on a private source repo default to **private**. The first time you publish a brand-new image (different repo, different name), flip it to Public via github.com → your packages → fendix → Package settings → Change visibility → Public. Existing `:latest` and `:X.Y.Z` tags don't need re-flipping.

### `release` matrix or `publish` failed

- These are the simplest jobs (just `go build` + `gh release create`). If they fail, it's usually a real build error.
- `gh run view <id> --log-failed | grep -E "FAIL|error"`
- Fix on main; either re-tag (`gh release delete vX.Y.Z --cleanup-tag --yes`, then re-tag from fixed HEAD), or cut the next patch.

### Re-tag vs. cut next patch — when to choose which

| Situation | Action |
|---|---|
| The release was never visible to anyone (no install path works) | **Re-tag.** v0.4.1's first attempt was redone this way. |
| Some users may have already pulled the broken release | **Cut next patch.** Re-tagging the same version is harmful — caches and tags propagate fast. |
| Workflow failed before any user-facing artifact was published | **Re-tag.** Cleaner history. |

To re-tag:

```bash
gh release delete vX.Y.Z -R Fendix-app/Fendix --cleanup-tag --yes
git tag -d vX.Y.Z
# fix on main, push, then:
git tag -a vX.Y.Z -m "..."
git push origin vX.Y.Z
```

---

## What's permanent vs. what's per-release

**One-time setup (already done; don't redo):**

- Public mirror repo: `Fendix-app/homebrew-fendix`
- `DIST_REPO_TOKEN` secret on engine repo (PAT with `Contents: write` on the mirror)
- Docker Hub repository metadata and CI credentials configured for `fendixapp/fendix`
- Homebrew tap usable as `brew tap Fendix-app/fendix`

**Every release:**

- Roll CHANGELOG, commit, tag, push, verify. That's it.

---

## Known limitations / planned improvements

These are non-blocking but worth knowing:

- **Docker `version` string is hardcoded as `docker`** — `docker run fendix version` shows `fendix version docker` instead of the real `vX.Y.Z`. Cosmetic; fix is a 1-line change in the Dockerfile (`-X main.Version=docker` at `Dockerfile:35`) to read the real version. Worth folding into the next patch. **Still open.**

### Shipped — no longer limitations

Everything below landed in Phase 13 and is live in the pipeline today. Verify
any of it against `.github/workflows/release.yml` before re-listing it as a gap.

- **linux/arm64 binary** — shipped. The `release` job matrix builds four targets: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64. The Docker `buildx` step publishes a `linux/amd64,linux/arm64` multi-arch manifest, so Apple Silicon + arm64 cloud runners no longer need `--platform linux/amd64`.
- **Signed binaries** — shipped. Cosign keyless (Sigstore Fulcio + GitHub Actions OIDC) signs each binary, the `.deb`/`.rpm`, the SBOMs and the Docker image, plus SLSA v1.0 build provenance. The `enforce-signing` job **fails any `v*` tag** unless `vars.COSIGN_ENABLED=true` (or the explicit `allow-unsigned` escape hatch), so an unsigned official release cannot happen by accident. Verification recipes: [`SECURITY.md`](SECURITY.md) → "Verifying release artifacts".
- **`get.fendix.dev` short-URL installer** — shipped (TASK-100). `curl -fsSL https://get.fendix.dev/install.sh | sh` is live; the domain is a CNAME to the public `homebrew-fendix` mirror served via GitHub Pages, with `raw.githubusercontent.com` as the documented fallback. `README.md` install section already leads with it.
- **`.deb` / `.rpm` packages** — shipped (TASK-100). `nfpm` (pinned `v2.40.0`) builds both from every linux binary in the matrix using `nfpm.yaml`; both are cosign-signed and attached to the release.

`README.md`'s install section and `docs/install.md` already document all four —
they only need touching when a **new** install path is added.

---

## Discovery / awareness (the next bottleneck)

Now that anonymous installs work, the bottleneck is "no one knows Fendix exists." Some asymmetric-leverage moves:

- **Show HN post** — title + 1-paragraph hook + GitHub link to the mirror's release page. Best Tuesday or Wednesday morning ET.
- **r/devops, r/netsec** — same hook, more emphasis on hybrid scan + 16× CVE coverage on test fixtures.
- **awesome-* lists** — submit PRs to `awesome-security`, `awesome-devops-tools`, `awesome-go`. Low effort, long-tail traffic.
- **Comparison content** — "Fendix vs. ZAP/gitleaks/semgrep" blog post once you have benchmarks (Phase 13 / TASK-104).
- **Frontend marketing site** — already deployed; hook a real domain (`fendix.dev`?) to it before posting anywhere.

These are not engineering tasks but they're what turns a working tool into an adopted one.
