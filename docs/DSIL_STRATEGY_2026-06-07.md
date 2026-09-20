# Fendix as a Developer Security Intelligence Layer — Next-Phase Strategy

**Date:** 2026-06-07
**Author:** Strategy review (CTO/DD lens)
**Decision inputs:** Center of gravity = *smarter scanner on its own engine* · Win = *OSS adoption / distribution* · Capacity = *strategy-first, scale to fit*
**Builds on:** [quarter_plan.md](quarter_plan.md) (engine-first v0.8→v0.11), [ADR-007](adr/ADR-007-open-source.md) (MIT engine), [ADR-008](adr/ADR-008-readonly-ai.md) (read-only AI in backend)
**Supersedes:** nothing — this *reframes* the existing release plan around a product thesis and a distribution goal.

---

## 0. The thesis, in one paragraph

A scanner *finds* problems. A **Developer Security Intelligence Layer (DSIL)** decides which problems are *real, reachable, and worth a developer's next 10 minutes* — and explains why, with proof, in the place the developer already works (the PR). Fendix already has the two hard halves of this (a hybrid detection engine + cross-engine correlation). The DSIL move is to stop positioning as "a scanner with good detection" and start positioning as **"the layer that turns raw findings into ranked, proven, explained, developer-ready intelligence."** Critically — given your goal — *the intelligence layer is also what generates the proprietary data (which findings developers accept vs. dismiss) that becomes the only real moat.* Adoption feeds the moat; the moat is impossible without adoption. So adoption-first is correct.

```
        TODAY                                    DSIL
   ┌───────────────┐                   ┌──────────────────────────────┐
   │  DETECT       │                   │  DETECT  (own DAST+SAST+SCA) │
   │  CORRELATE    │   ──────────►     │  CORRELATE                   │
   │  REPORT       │                   │  ┌────────────────────────┐  │
   └───────────────┘                   │  │ INTELLIGENCE LAYER     │  │
                                       │  │ • reachability proof   │  │
   "Here are 119 findings."            │  │ • rank / prioritize    │  │
                                       │  │ • explain (why + fix)  │  │
                                       │  │ • learn from accept/   │  │
                                       │  │   dismiss feedback ◄───┼──┼── the moat
                                       │  └────────────────────────┘  │
                                       │  DELIVER in the PR           │
                                       └──────────────────────────────┘
                                       "Fix these 3 first. Here's the
                                        proof and the patch. We learned
                                        you ignore the other 116."
```

---

## 1. What this changes vs. your current plan (and what it doesn't)

Your `quarter_plan.md` is *right* on sequencing — I'm not asking you to throw it away. I'm asking you to **re-label its outputs as intelligence-layer capabilities** and add three things it's missing for a distribution-led DSIL play.

| Your quarter_plan workstream | DSIL reframe | Keep / Change |
|---|---|---|
| WS1 — Detection + FP reduction (v0.8) | **"Trust" pillar** — the layer is only believed if it's accurate. FP corpus → *training data for the ranking model later.* | **Keep, re-frame.** This is the foundation. |
| WS2 — Performance / drop embedded Python (v0.9) | **"Ubiquity" pillar** — a sub-500ms single binary is what makes it adoptable everywhere (the distribution enabler). | **Keep.** Critical for adoption. |
| WS3 — Plugin ecosystem (v0.10) | **"Openness" pillar** — but re-aim: plugins are an *ingestion port*, not just custom checks. Even staying own-engine, the NDJSON contract is how the community extends the layer. | **Keep, sharpen the docs/positioning.** |
| WS4 — Detection round 2 from real data (v0.11) | **"Learning" pillar** — this is where the feedback loop *starts*. Don't just fix FPs; **instrument** them. | **Keep, add instrumentation.** |
| *(missing)* | **Prioritization / ranking** — the single most DSIL-defining capability and you don't have it yet. | **ADD.** |
| *(missing)* | **Feedback capture** — accept/dismiss signal is the moat substrate. Capturable *in OSS* via the ignore-file + (opt-in) the backend. | **ADD.** |
| *(missing)* | **The narrative + launch** — adoption doesn't happen because the engine is good; it happens because the story travels. | **ADD (parallel track).** |

**Net:** keep the four workstreams, insert *prioritization* and *feedback instrumentation* as first-class, and run the launch as a parallel track instead of "after v0.11." Waiting 5 months to launch is the single biggest mistake in the current plan **for an adoption goal** — you launch to *get* the real-world FP data WS4 depends on. Launch is an input, not a reward.

---

## 2. The DSIL capability stack (what "intelligence" concretely means)

Five layers. You have 2.5 of them. Build the rest in order — each is only believable once the one below it is solid.

| Layer | What it is | Status today | Defensibility |
|---|---|---|---|
| **1. Detect** | DAST + SAST + SCA + secrets + IaC on own engines | ✅ Strong | Low (commodity) |
| **2. Correlate** | Cross-engine agreement; dedup | ✅ Real | Medium (uncommon) |
| **3. Prove** | Reachability / taint chain → "this input reaches this sink" | ⚠️ Partial (Go + Py, not JS) | Medium-High |
| **4. Prioritize** | Rank findings by *reachable × exploitable × exposed × business-context* | ❌ Missing | **High** (this is the DSIL identity) |
| **5. Explain & Learn** | Why it matters, how to fix, + learns from accept/dismiss | ❌ Missing (ADR-008 opens AI door) | **Highest** (the data moat) |

> **Insight:** Layers 1–3 make you *a good scanner*. Layers **4–5 make you an intelligence layer.** The legacy message overemphasized correlation while the product already sat at layer 3. The whole repositioning is: *finish 3, build 4, start 5 — and say so.*

---

## 3. The phased plan (sequenced, capacity-agnostic)

Each phase is a *theme with a shippable artifact and a public story*. Run them in order; scale the day-counts to your real capacity. I've kept the work small and high-leverage because you're solo and adoption-led.

### Phase 1 — TRUST & LAUNCH (the foundation + the first story)
*Reframe of WS1 + the launch that your current plan defers.*

**Goal:** an accurate engine that's *believed*, in front of *people*, generating *real FP data*.

- **1a. Close the credibility-killers first (1–2 weeks).** Before any launch, fix the trust-claim contradictions from the diligence: the false *"Zero outbound"* README line, the no-op `--offline` flag, and the fail-open behaviors (scanner errors → silent clean, AST recursion bomb → false all-clear). **For a security tool launched to a skeptical HN/Reddit audience, one `tcpdump` that contradicts your README ends the launch.** This is non-negotiable and comes before everything.
- **1b. Ship WS1 detection + FP reduction (v0.8).** As planned. The FP corpus you build here is *seed training data* for Phase 3 ranking — treat it as such (structured, labeled, kept).
- **1c. Launch in parallel** (the marketing-plan.md Phase 0–1). Show HN, GitHub Marketplace, the comparison-SEO pages. **You launch to acquire the real-world FP stream**, not after you've polished everything.
- **Public story:** *"A CI scanner that proves the bug before it fails your build — and here's our honest accuracy methodology."* The honesty IS the differentiation in a category full of FP-spam.
- **Artifact:** v0.8 + a live repo + first 50–200 installs + an inbound FP stream.

**Why first:** Adoption goal means traffic is oxygen. Everything downstream (ranking, learning) needs real findings from real repos, which needs users, which needs launch. And launch needs the trust claims to be true.

---

### Phase 2 — UBIQUITY (be everywhere a developer runs code)
*Reframe of WS2 (perf) + distribution surface expansion.*

**Goal:** remove every reason *not* to run Fendix. A DSIL is only intelligent about code it sees; adoption breadth = intelligence breadth.

- **2a. Ship WS2 perf (v0.9).** Drop embedded Python, port secrets to Go, sub-500ms cold start. **This is the adoption multiplier** — a 4× faster single binary is what makes it frictionless in every pipeline, pre-commit hook, and IDE.
- **2b. Expand the distribution surface (the part WS2 doesn't cover):**
  - **GitHub Action** (first-class, in Marketplace) — the #1 adoption channel for this category.
  - **pre-commit hook** + **`fendix init`** for one-command CI wiring.
  - **SARIF → GitHub Code Scanning** polish (you have SARIF; make the Code Scanning tab experience clean — that's free distribution inside every GitHub repo).
- **Public story:** *"Fendix now cold-starts in <500ms. One binary, every pipeline, zero telemetry."*
- **Artifact:** v0.9 + GitHub Action + pre-commit + clean Code Scanning integration.

**Why second:** Speed and surface area are what convert *launch spike* into *sustained installs*. Do this before the smart layers so the smart layers run everywhere.

---

### Phase 3 — PRIORITIZE (become an *intelligence* layer, not a scanner)
*The new, missing, DSIL-defining work. This is the phase that earns the name.*

**Goal:** stop emitting a *list*; start emitting a *ranking with a defensible reason*. This is the single highest-leverage product change you can make.

- **3a. A real prioritization model (deterministic first, no ML, no LLM).** A transparent scoring function over signals you already compute or can cheaply add:
  - `reachable` (you have it) — proven taint chain ranks above pattern match.
  - `correlated` (you have it) — both-engines-agree ranks above single-engine.
  - `exploitability` — active-probe-confirmed (you have it for injection) ranks highest.
  - `exposure` — internet-facing endpoint > internal (derive from the DAST crawl).
  - `CVE severity + EPSS/KEV` for SCA findings (EPSS/KEV are *free public feeds* — high ROI, your quarter_plan even flags `reachable_code` multiplier as underused).
  - Output: a stable **`fendix_priority` score (0–100)** + a one-line *"why this ranks here"* rationale on every finding.
- **3b. "Fix these N first" UX.** The PR comment and CLI lead with the top-ranked few, collapse the rest. *This is the felt product difference* — a developer sees 3 things to do, not 119.
- **3c. Keep it deterministic and explainable.** No LLM here (that's Phase 5). A transparent, auditable score is *more* trustworthy than a black box and fits your trust brand. It also becomes the **label schema** for any future ML ranker.
- **Public story:** *"Fendix doesn't just find bugs — it tells you which 3 to fix first, and shows its work."* This is the post that re-frames you from "scanner" to "intelligence layer" in the market's mind.
- **Artifact:** v0.10 (or a dedicated release) with `fendix_priority` + ranked output. **This is your strongest single piece of launch-able content all year.**

**Why third:** It needs accurate detection (Phase 1) and it needs to run everywhere (Phase 2) to matter — but it does *not* need the feedback loop yet. Ship deterministic ranking now; learn to tune it in Phase 5.

---

### Phase 4 — OPENNESS (the contract that lets the community extend the layer)
*Reframe of WS3 (plugins).*

**Goal:** make the intelligence layer *extensible* without you writing every check — the OSS-adoption flywheel.

- **4a. Ship WS3 plugin ecosystem (v0.10/v0.11)** as planned: external-author docs, 2 non-Go reference plugins, `fendix plugins install`, CI smoke tests.
- **4b. Frame plugins as the ingestion port.** Even staying own-engine, document that a plugin can *import another tool's findings* (a Grype/Trivy importer reference plugin) — this is the cheapest possible hedge toward the aggregation-platform future you deferred, costing nothing now but keeping the option open. The `models.Finding` waist already supports it.
- **4c. Security-harden the plugin runner first** (diligence F-H2: repo-local plugin RCE from untrusted PRs). An *open* extension system that's also an RCE vector is a launch-day CVE waiting to happen. Allowlist + ownership/symlink checks before exec.
- **Public story:** *"Write a Fendix plugin in any language in 20 lines. Here are three."*
- **Artifact:** stable, documented, *safe* plugin contract + community-contributable surface.

**Why fourth:** Per your own quarter_plan reasoning — the perf work (Phase 2) may shift the NDJSON contract, so stabilize and document it *after* v0.9. Openness compounds adoption but only once the core is fast and accurate.

---

### Phase 5 — LEARN (the moat) + read-only AI explanation
*Reframe of WS4 + the ADR-008 AI work, now properly sequenced last.*

**Goal:** turn usage into a compounding, non-replicable asset — and add the AI explanation layer *on top of* a ranking that's already good.

- **5a. Instrument the feedback loop (the moat substrate).** Every time a developer suppresses, ignores, or fixes a finding, that's a *label*. Capture it:
  - In OSS: the `.fendix-ignore` file already encodes dismissals — parse it as signal (local, no telemetry — respects your zero-telemetry brand).
  - In the backend (opt-in, authenticated users): accept/dismiss/fixed events on findings. *This is the data competitors can't clone* — it's tied to your installed base.
- **5b. Tune the Phase-3 ranking from real labels** (this is WS4's "fix the FPs users actually hit," done as *ranking improvement*, not just rule fixes).
- **5c. Read-only AI explanation (ADR-008), in the backend only.** Now it's grounded: AI explains *findings that are already ranked and proven*, so the LLM amplifies signal instead of noise (exactly ADR-008's precondition). Keep it strictly read-only, clearly labeled, never in the OSS engine's SARIF/JSON. This becomes a *Pro* feature — the first thing worth paying for — without compromising the OSS trust anchor.
- **Public story:** *"Fendix learns which findings your team actually fixes — and explains the ones that matter."*
- **Artifact:** a ranking that measurably improves with usage + an AI explanation endpoint (Pro).

**Why last:** Per ADR-008's own logic, AI on noisy findings amplifies noise — it must come *after* accurate detection (P1), ubiquity (P2), and good deterministic ranking (P3). And the learning loop needs an installed base (P1 launch) to have anything to learn from. This phase is where adoption *becomes* moat.

---

## 4. The sequence at a glance

```
 P1 TRUST+LAUNCH ──► P2 UBIQUITY ──► P3 PRIORITIZE ──► P4 OPENNESS ──► P5 LEARN+AI
 (accuracy +         (perf +         (ranking +        (safe plugin     (feedback loop
  honest claims +     surface)        "fix these 3")    ecosystem +       + read-only AI
  LAUNCH)                             ◄── the rename     ingestion port)   = the moat)
      │                                    moment             │                 │
      └── starts the real-world FP stream that P5 needs ──────┴─────────────────┘
```

**The one re-sequencing that matters most:** launch in **P1**, not after P5. Your current plan launches in "Q0 parallel to WS1" which is right — this strategy just makes it explicit and load-bearing: *the launch is what generates the data the intelligence layer learns from.*

---

## 5. Each recommendation, scored

| # | Recommendation | Impact | Effort | Priority | Expected ROI |
|---|---|---|---|---|---|
| R1 | Fix trust-claim contradictions + fail-open **before launch** | Brand-survival | Low (1–2wk) | **P0** | Very high — prevents a launch-day credibility collapse |
| R2 | Launch in Phase 1 (don't wait for v0.11) to start the FP/feedback stream | Adoption + data | Low (plan exists) | **P0** | Very high — data is the moat substrate; it only flows from users |
| R3 | Build deterministic prioritization (`fendix_priority` + "fix these 3") | Repositions scanner→intelligence layer | Medium | **P0** | Very high — *the* DSIL-defining capability + best content of the year |
| R4 | Sub-500ms perf + GitHub Action + pre-commit + Code Scanning polish | Adoption multiplier | Medium (WS2 + extras) | **P1** | High — converts launch spike into sustained installs |
| R5 | Instrument accept/dismiss/fix as labeled feedback (OSS local + opt-in backend) | The moat | Low-Med | **P1** | Highest long-term — turns adoption into defensibility |
| R6 | Add EPSS/KEV to SCA ranking (free public feeds) | Prioritization quality | Low | **P1** | High — cheap, credible, expected by buyers |
| R7 | Security-harden the plugin runner before promoting the ecosystem | Prevents launch-day CVE | Low-Med | **P1** | High — an RCE in a *security* tool is existential |
| R8 | Read-only AI explanation in backend, Pro-gated, post-ranking (ADR-008) | First monetizable feature | Medium | **P2** | Medium-high — revenue later, but only valuable atop good ranking |
| R9 | Document plugins as an ingestion port (Grype/Trivy importer reference) | Platform optionality | Low | **P2** | Medium — keeps the aggregation-future open at ~zero cost now |
| R10 | Keep ranking deterministic/explainable (no black-box ML yet) | Trust + future label schema | — (a constraint) | **P2** | High — fits brand; sets up ML later with clean labels |

---

## 6. What to explicitly NOT do (the discipline that makes solo+adoption work)

- **Don't build the aggregation/ASPM platform yet.** You chose own-engine; ingesting Snyk/Semgrep is a different company. Keep the *option* (R9) at zero cost, but don't build it. It needs enterprise customers you don't have.
- **Don't build org/RBAC/SSO/SOC2 now.** Adoption goal = developers, not CISOs. These are revenue-phase, not adoption-phase. (Also: pull or hide the "Team — 10 seats" plan until the org model exists; pricing a capability you can't deliver is a credibility leak.)
- **Don't put AI in the OSS engine.** ADR-008 is right. AI in the backend, labeled, read-only. The OSS trust anchor is worth more than the AI feature.
- **Don't do black-box ML ranking before you have labels.** Deterministic first (P3), learn from real data (P5), ML only when the labeled feedback corpus is big enough to beat the deterministic baseline.
- **Don't gate core detection behind Pro.** Adoption requires the scanner to stay generously free. Monetize *intelligence convenience* (hosted history, AI explanation, team features), never *detection*.

---

## 7. The 90-second pitch after this plan

> **Before:** Correlation-only DAST + SAST positioning.
> **After:** "Fendix is the developer security intelligence layer. It runs SAST, DAST, and dependency scanning in one CI check, **proves** which findings are actually reachable, **ranks** them so you fix the 3 that matter instead of triaging 119, and **learns** which findings your team actually acts on. Open source, single binary, no telemetry — and it gets smarter the more you use it."

That last clause — *gets smarter the more you use it* — is the sentence that turns a replicable scanner into a fundable intelligence layer, and it's only true if you ship the feedback loop (P5) on top of an adopted base (P1). Everything in this plan serves that sentence.

---

## 8. Immediate next 3 actions

1. **This week:** fix the three trust-claim contradictions (R1). They block the launch and they're 1–2 weeks of work, mostly deletion and disclosure.
2. **Next:** finish WS1 detection+FP (v0.8) **and** prep the launch in parallel (the marketing plan is already written — execute Phase 0).
3. **Then:** make the prioritization spike (R3) your next big build — it's the capability that earns the name "intelligence layer" and gives you the single best launch-able story you have.
