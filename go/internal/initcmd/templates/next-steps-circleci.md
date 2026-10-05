# Fendix — CircleCI next steps

`fendix init --ci circleci` wrote `.circleci/fendix-config.yml`.
**CircleCI does not auto-merge multiple config files** — you must
fold this snippet into your existing `.circleci/config.yml`. Two
options:

## Option A — single `config.yml` (most projects)

Open `.circleci/config.yml` and merge by section:

1. **`jobs:`** — copy the `fendix-scan:` job from
   `fendix-config.yml` into your top-level `jobs:` block.
2. **`workflows:`** — add an entry to your existing workflow OR
   keep `security:` as a separate workflow alongside your existing
   ones (CircleCI runs all workflows in parallel by default).

Then delete `.circleci/fendix-config.yml` — it's no longer needed
once the content is merged.

## Option B — keep `fendix-config.yml` as a separate file

CircleCI v2.1 supports config-file splitting via the `setup` /
`continuation` flow. If you're already using that pattern, add
`fendix-config.yml` as one of the continuation configs from your
`setup` step. See [the upstream docs][continuation-docs] for the
exact wiring.

[continuation-docs]: https://circleci.com/docs/dynamic-config/

## Pinning the Fendix version

`fendix init` pins `FENDIX_VERSION` in `fendix-config.yml` to the
Fendix release that generated it, so every run installs the same
verified binary. To upgrade, change it to a newer tag from
<https://github.com/Fendix-app/Fendix/releases>:

```yaml
environment:
  FENDIX_VERSION: "vX.Y.Z"
```

The install step rejects anything that is not a release tag, including
"latest". Install cosign in the job image to have the installer verify
the release signature as well as its checksum.

## Commit

```bash
git add .circleci/fendix-config.yml NEXT-STEPS-fendix.md
git commit -m "Add Fendix security scanning"
```
