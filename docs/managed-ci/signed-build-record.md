# Signed engine build record (managed CI, ADR-010)

Status: **design, not implemented.** The schema is
`contracts/engine-build-record/v1/build-record.schema.json`.

Managed CI accepts evidence only from an engine build the operator approved.
Today that approval is a list of `version=digest` pairs in an environment
variable, maintained by hand. This replaces it with a signed record produced
by the release pipeline and imported once, administratively.

## What the record is

One statement per release, signed by the release workflow's keyless GitHub
Actions identity, binding together:

| Field                                                                     | Why it is in the record                                                                                             |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `engine_version`                                                          | What the executable reports, so a submission's version can be compared rather than assumed.                         |
| `source.repository`, `source.commit`, `source.tag`                        | Which sources produced it. A digest with no provenance says only "some binary".                                     |
| `artifacts[].executable_sha256`                                           | The identity managed evidence actually carries.                                                                     |
| `artifacts[].os`, `artifacts[].architecture`                              | Digests differ per platform, so each is pinned separately.                                                          |
| `artifacts[].download_name`                                               | Ties the record to the published asset for humans and the installer.                                                |
| `contract.revision`, `contract.bundle_sha256`                             | Which canonical contract the build implements, and that the bundle's contents match that revision.                  |
| `contract.finding_policy_version`                                         | Which policy's vectors it reproduces, so the backend interprets evidence under the policy the producer implemented. |
| `workflow.identity`, `workflow.issuer`, `workflow.ref`, `workflow.run_id` | Who the signer must be, so the signature can be compared with an expectation instead of merely existing.            |
| `created_at`, `schema_version`                                            | When it was made, and how to read it.                                                                               |

**The executable digest is the digest of the executable.** Not the release
archive, not a container manifest, not a source tree hash. Managed evidence
carries the digest of the _running binary_ (the engine hashes itself, because a
digest compiled in with ldflags cannot describe the binary containing it), and
only the same kind of digest can ever match it.

## Where verification happens

**At approval time, administratively — not on every CI submission.**

Verifying a signature on the ingestion path would put a network dependency and
a transparency-log lookup in front of every customer scan: an outage would
become a managed-CI outage, and the timeout would be a decision the customer
did not get. Approval happens once per release, by an operator, and produces a
stored fact.

At approval the backend must verify, before storing anything:

1. the signature is valid for the record bytes;
2. the certificate's issuer equals `workflow.issuer`;
3. the certificate's workflow identity equals `workflow.identity`;
4. the certificate's source repository equals `source.repository`;
5. the certificate's ref/tag equals `workflow.ref` and `source.tag`;
6. the signed subject digest equals the record's own digest;
7. the record validates against `engine-build-record/v1`.

Then it stores the **immutable** record together with the original signed
bytes and the verification result, and audits the approval. Withdrawal and
rejection are audited the same way — a build that is withdrawn must leave a
trace of _when_ it stopped being acceptable, because decisions made before
that moment were legitimate and decisions after it were not.

## What ingestion checks

For each submission, the engine block must match **one active record exactly**:

- `engine.version` equals `engine_version`;
- `engine.build_digest` equals one `artifacts[].executable_sha256`;
- the contract revision the backend is running equals `contract.revision`;
- `engine.finding_policy_version` equals `contract.finding_policy_version`.

Unknown, mismatched, expired and withdrawn builds fail closed with
`unsupported_version`. **Version alone is never sufficient**: it is a string
the submitter controls, and two binaries can report the same one.

Once a deployment has imported **any** record, the records are authoritative
— not only while one is active. Otherwise withdrawing the last active record
would fall back to whatever bootstrap allowlist the deployment started with,
and that allowlist still names the build just withdrawn, so the withdrawal
would accept exactly what it was issued to stop. Withdrawing every record
accepts nothing, which is the direction this control fails.

## Threat model

| Threat                                                                     | What stops it                                                                                                                            |
| -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| A modified engine that emits favourable facts                              | The executable digest is pinned. A patched binary hashes differently and matches no record.                                              |
| A genuine but unapproved build (a fork, a local `go build`, a pre-release) | The digest is not in any record; the operator never approved it.                                                                         |
| A forged record                                                            | The signature must verify against the release workflow's keyless identity.                                                               |
| A record signed by another workflow in the same repository                 | The certificate's workflow identity must equal `workflow.identity`, not merely belong to the org.                                        |
| A record signed by a look-alike repository                                 | The certificate's repository must equal `source.repository`.                                                                             |
| Replaying an old record after a build is withdrawn                         | Only active records are matched, and withdrawal is a stored, audited state change.                                                       |
| Swapping the artifact list under a valid signature                         | The signed subject digest covers the record bytes, so any edit invalidates it.                                                           |
| A record naming an archive checksum instead of the executable's            | The schema says `executable_sha256`, and ingestion compares it with the self-hash the engine reports; an archive digest can never match. |
| A build whose contract bundle differs from the revision it names           | `contract.bundle_sha256` is compared with the bundle at that revision.                                                                   |
| Evidence produced under a different policy than the backend interprets     | `contract.finding_policy_version` must equal what the submission declares.                                                               |
| Signing-infrastructure outage blocking customer scans                      | Verification is at approval time; ingestion reads a stored fact.                                                                         |
| An operator approving the wrong build by mistake                           | Approval records who approved what, and is auditable and reversible.                                                                     |

**Not covered.** The record says a build is genuine, not that a _scan_ was
honest: the customer's runner still chooses what to scan and can scan
nothing. That is the residual risk ADR-010 accepts for the pilot, and it is
why coverage is evidence the backend judges rather than a claim it trusts.
Reproducible builds would let a third party confirm the digest follows from
the sources; the record does not assert that today.

## Implementation plan

1. **Release pipeline** — after artifacts are built, emit the record, sign it
   with the keyless release identity, and publish it as a release asset
   alongside the checksums.
2. **Backend** — a model for an approved build (immutable, storing the record,
   the signed bytes and the verification result), an operator command to
   import, approve and withdraw, and audit events for each.
3. **Backend ingestion** — replace `MANAGED_CI_ACCEPTED_ENGINE_BUILDS` with a
   lookup against active records, keeping the same fail-closed
   `unsupported_version` behaviour.
4. **Migration** — the pilot's current pair list becomes the first imported
   record for the engine release that ships the exporter.

Until step 3 ships, the environment allowlist stays authoritative, and it is
a pre-enablement gate.
