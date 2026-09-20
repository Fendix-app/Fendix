# `get.fendix.dev` compatibility host

These files are synchronized into the legacy public distribution mirror
`Abdel-RahmanSaied/homebrew-fendix` by `.github/workflows/release.yml`.
GitHub Pages currently serves the custom domain `get.fendix.dev` from that
mirror.

- `index.html` removes the retired marketing copy and sends browsers to
  `https://www.fendix.dev/docs/getting-started` using a canonical link,
  immediate meta refresh, and `location.replace` fallback.
- `CNAME` keeps the existing GitHub Pages custom-domain binding.
- `.nojekyll` disables Jekyll processing.
- `scripts/install.sh` is copied separately to `/install.sh` for existing
  curl-based installations.

GitHub Pages always returns `200` for `index.html`; it cannot emit the required
server-side `301` or `308`. The permanent fix is an infrastructure change:
move the `get.fendix.dev` DNS record to a redirect-capable host and configure
`/` and `/index.html` to return `308` to the canonical documentation URL.
Keep `/install.sh` serving the verified installer until a brand-owned script
endpoint exists, then redirect that path separately to the script rather than
to an HTML page. See `docs/container-registry-migration.md` for the cutover and
verification steps.

The engine source repository is public at
<https://github.com/Fendix-app/Fendix>. The personal-name distribution mirror
is retained only for binary/Homebrew compatibility until a brand-owned mirror
is provisioned.
