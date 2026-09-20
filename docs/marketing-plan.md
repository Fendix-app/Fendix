# Fendix — 90-Day Marketing Plan

> ⚠️ Accuracy figures below are superseded by **[BENCHMARKS.md](../BENCHMARKS.md)**
> (the reproducible source of truth). Current synthetic corpus: **F1 1.000**
> (38/38, reproduced + CI-gated) — v0.26 disclosed one multi-hop SSRF false
> negative (then 0.987); v0.27 fixed the taint engine, so 1.000 is now
> legitimate, not the stale v0.11.0 claim. "1.000 recall" elsewhere also refers
> to the real-world expectation-recall track (44/44 CVE-anchored repos).

> Status: **draft v1**, 2026-05-25
> Stage assumed: pre-launch (repo private), zero budget, solo operator
> North star: **OSS adoption → email list → SaaS funnel for the planned fendix-backend**
> Companion docs: [launch-post.md](launch-post.md) (channel copy), [marketplace-listing.md](marketplace-listing.md) (GitHub App), [accuracy.md](accuracy.md) (claims backing every headline)

---

## 1. Why this plan, and what I'm explicitly NOT doing

| Doing | Not doing | Reason |
|---|---|---|
| Organic OSS launch on HN / Reddit / Lobste.rs | Cold outbound sales | Zero budget, no case studies, security buyers don't take cold |
| Email capture from day 1 | Closed beta waitlists | Friction kills early adoption; capture interest without gating product |
| Honest accuracy numbers (0.987 F1 / 1.000 recall / 44/44 real-world) | Cherry-picked 1.000 F1 from v0.11 era | Honesty is the brand; "0 false negatives" is a stronger story than "0 false positives" anyway |
| GitHub Marketplace listing | Product Hunt | Security tools die on PH; HN is where the target audience reads |
| Long-form "what we found" content | Generic "5 reasons to use a scanner" blogspam | Differentiation = depth |
| GitHub Discussions, OWASP local chapters | LinkedIn thought-leadership posting | LinkedIn ≠ DevTool top-of-funnel |

---

## 2. Audience — concentric rings

| Ring | Who | Why they care | What I say to them |
|---|---|---|---|
| **R1 — Peers / evaluators** | Go developers, AppSec engineers, ex-Snyk/Semgrep/Detectify staff | Technical depth + accuracy methodology | Architecture posts, race-clean code, ADRs, plugin contract |
| **R2 — Adopters** | DevOps / platform engineers at 50–500-person orgs | "I'm tired of triaging false positives in CI" | Single binary, CI-ready, `--fail-on` gate, correlation explanation |
| **R3 — Buyers (future SaaS)** | Eng leaders, CISOs, AppSec managers | Compliance, dashboards, AI explanations | Email capture today; SaaS pitch when backend ships |
| **R4 — Amplifiers** | DevTool podcasters, newsletter curators, OWASP chapter leads | Story to tell their audience | Pitch them with the v0.15 accuracy story + real-world findings |

Optimize copy and channel for **R1 first** (they grant credibility) → R2 follows organically → R3 enters the funnel passively via email.

---

## 3. The 90 days at a glance

```
WEEK   1   2   3   4   5   6   7   8   9   10  11  12  13
       ├───┴───┤  ├───┤  ├───────────────────────────────┤
       PRELAUNCH    LAUNCH      SUSTAIN + COMPOUND
                    WEEK
```

| Phase | Weeks | Theme | Headline KPI |
|---|---|---|---|
| **Phase 0 — Pre-launch** | 1–2 | "Make the rocket ready" | All prereqs shipped; 10 peer reviewers gave feedback |
| **Phase 1 — Launch week** | 3 | "Show HN Tuesday" | #1 on HN front page; 500+ stars; 100+ email signups |
| **Phase 2 — Sustain** | 4–12 | "Compound credibility" | 3k stars; 1000 signups; 3 design-partner convos |
| **Phase 3 — Quarterly review** | 13 | Decide what worked, what to kill | Next-quarter plan written |

---

## 4. Phase 0 — Pre-launch (Weeks 1–2)

**Goal:** when you press "publish" on HN, every reflex is paid down. Zero last-minute scramble.

### 4.1 Prereqs you MUST ship before launching (in priority order)

| # | Task | Effort | Why |
|---|---|---|---|
| 1 | **Refresh `docs/launch-post.md` to v0.15 numbers** | 1 hr | Current draft says v0.11; outdated numbers = obvious unreviewed copy on HN |
| 2 | **Make repo public** | 5 min | Self-explanatory. Schedule for ~24h before launch so search engines start indexing |
| 3 | **Landing page at `fendix.dev`** (you already own the CNAME per README) | 4 hr | Single HTML on GitHub Pages: hero, 3 bullets, install one-liner, demo GIF, "get notified" email form |
| 4 | **Email capture** — [Buttondown](https://buttondown.email) free tier (100 subs) or [ConvertKit](https://convertkit.com) free | 30 min | This is the SaaS funnel. Form on landing page + footer of `README.md` |
| 5 | **Analytics** — [GoatCounter](https://goatcounter.com) or [Plausible](https://plausible.io) free OSS | 30 min | Need to know what hits and from where. No GA. |
| 6 | **Demo GIF** (60 sec asciinema → MP4) | 1 hr | One scan against juice-shop, rendered HTML report opens at end |
| 7 | **GitHub Discussions enabled, with seed posts** ("show off your plugin", "what would you want?") | 30 min | HN traffic needs a place to land that isn't an issue |
| 8 | **Contributor guide refresh** ([CONTRIBUTING.md](../CONTRIBUTING.md)) — make first PR ergonomic | 1 hr | OSS converts visitors to contributors only if the path is obvious |
| 9 | **5 "good first issue" labels** on real issues | 30 min | Same reason. Hacktoberfest-able. |
| 10 | **Submit GitHub Marketplace listing** (copy in [marketplace-listing.md](marketplace-listing.md) already drafted) | 1 hr | App review takes 5–10 business days. Start in week 1 so it's live by launch |
| 11 | **Show 10 peers privately** — gather feedback | spread over both weeks | Catches obvious copy bugs / claims that can't be defended on HN |

### 4.2 Headline-number decision (must do before refreshing copy)

You have a real choice here that will shape the launch:

- **Option A — "F1 = 1.000 on labeled corpus" (the v0.11 claim)**. Defensible only if you tune the harness to handle compound multi-endpoint findings (the line 36 issue from today's E2E run). Effort: ~2 hr of work in `scripts/accuracy/run.py`.
- **Option B — "1.000 synthetic F1 (38/38, reproduced + CI-gated; the v0.26 SSRF FN was fixed in v0.27), 44/44 expectations met on 13 real-world CVE-anchored repos"**. This is what current `main` actually produces (see BENCHMARKS.md) — and unlike the v0.11-era 1.000, it now reproduces and is CI-gated.

**My recommendation: Option B.** Real-world numbers are a stronger story than synthetic corpus perfection. "0 false negatives across 13 CVE-anchored real repos" is what an AppSec engineer actually wants to hear. Update [launch-post.md](launch-post.md) accordingly.

### 4.3 Pre-launch content (write these now, schedule for Phase 2)

Have these three drafts ready BEFORE launch so you have something to publish in weeks 4–6 when launch attention fades:

1. **"How Fendix correlates DAST and SAST"** — architecture deep-dive, the wedge of the product
2. **"We scanned the top 100 Python OSS projects — here's what we found"** — needs a real one-evening scan run + write-up
3. **"Why our scanner doesn't call an LLM"** — riff on ADR-008, philosophical post for HN amplification

---

## 5. Phase 1 — Launch week (Week 3)

**Pick the week deliberately.** Avoid: US holidays, big-tech keynote days (Apple/Google/AWS announcements drown out HN), the week of a major Go release. Aim for a quiet Tuesday in a quiet week. Confirm with `https://news.ycombinator.com/front` for the previous month.

### 5.1 Daily schedule

| Day | Action | Channel | Time (US PT) | Notes |
|---|---|---|---|---|
| **Mon** | Final QA: install on 3 fresh machines (Linux, macOS, WSL); demo scan works | — | — | Catch any "doesn't install" rage before HN sees it |
| **Tue 06:30** | Show HN post live | HN | 06:30 PT (sweet spot for US morning + EU afternoon) | Title: see §5.2 |
| **Tue all day** | Respond to every comment within 10 min | HN | — | This is the work. Block calendar. |
| **Wed 09:00** | r/devops + r/programming (not r/golang yet — pace it) | Reddit | — | Different framing per sub; see [launch-post.md](launch-post.md) §"r/devops version" |
| **Thu 09:00** | r/golang + r/netsec + Twitter/X thread | Reddit + X | — | The /r/golang version is the most technical of the four |
| **Thu 13:00** | Lobste.rs submission | Lobste.rs | — | Slower-moving, smarter audience; quality > volume |
| **Fri 09:00** | First architecture blog post goes live | Personal blog or [Fendix blog page](https://fendix.dev/blog) | — | Cross-post link to HN comment thread; revives HN attention |
| **Fri all day** | Pitch 5 newsletters: KubeWeekly, Console.dev, Pointer, TLDR DevOps, GoTime podcast | Cold email + Twitter DMs | — | Templates in §5.4 |
| **Sat–Sun** | Monitor + respond. Do NOT cross-post to more places. Let it breathe. | All | — | Saturation kills momentum |

### 5.2 Show HN title — A/B candidates

Pick ONE on launch morning based on what's already on the HN front page (don't compete with similar titles):

- **A:** "Show HN: Fendix — DAST + SAST + SCA with evidence-based release decisions. (MIT, Go)"
- **B:** "Show HN: I scanned 13 known-vulnerable repos with my SAST engine — 44/44 expectations met (MIT, Go)"
- **C:** "Show HN: Fendix v0.15 — open source DAST+SAST scanner, no telemetry, single binary"

**Default: B.** Concrete result > abstract claim. Title B is also the most defensible against "I bet it's full of FPs" snipers because the result IS the answer to that.

### 5.3 What MUST be in the Show HN body (in order)

1. **What it is** in one sentence
2. **The wedge** (correlation gate — what makes it different)
3. **Concrete numbers** (one short paragraph; link to `docs/accuracy.md` for methodology)
4. **What it's NOT** (sets expectations; pre-empts "you should add X" comments)
5. **Install one-liner**
6. **Roadmap honesty** — mention the planned SaaS / AI-explanation layer in `fendix-backend`, ADR-008 forbids LLM calls from the OSS engine
7. **Ask** — specifically: "Feedback on the correlation gate. Is the NDJSON plugin contract too minimal?"

The v0.11 draft already has this shape. Refresh numbers + add a "What's new in v0.15" two-liner.

### 5.4 Outreach templates (Friday)

**Newsletter pitch (short, no PDF, no fluff):**
> Subject: Open-source DAST+SAST scanner, 44/44 on real CVE-anchored repos — fit for [newsletter]?
>
> Hi [name], built [Fendix](https://github.com/Fendix-app/Fendix) — solo, MIT, Go, single binary. Show HN today. Heads-up in case it's a fit for next week's [newsletter]. Headline: every dependency-CVE / taint-chain / hardcoded-secret expectation met on 13 deliberately-vulnerable repos (Juliet, pygoat, dvpwa, nodegoat, juice-shop, +8). No reply needed if not a fit.
>
> — Abdel

**Podcast pitch (also short):**
> Subject: 10-min segment: how to make a DAST+SAST gate that doesn't cry wolf
>
> Hi [name], shipped Fendix today — an open-source DAST + SAST + SCA scanner with evidence and confidence-aware release decisions. Strong deterministic evidence can block on its own; independent corroboration strengthens medium-confidence findings. There's an interesting architectural story (NDJSON-over-pipes IPC + Go orchestrator + opt-in Python AST analyzer) that may or may not be a fit for an episode. No deck, no demo required.
>
> Show HN: [link]. Repo: [link]. Happy to send 3-bullet outline if useful.
>
> — Abdel

---

## 6. Phase 2 — Sustain & compound (Weeks 4–12)

Launch attention dies in 72 hours. Weeks 4–12 are where you either build a flywheel or fade.

### 6.1 Cadence (commit to this, recover from misses next week)

| Frequency | Output | Channel | Effort |
|---|---|---|---|
| **Weekly** | "Caught in the wild" tweet — 1 real finding from a scan you ran that week, redacted | X / Mastodon / fendix.dev/blog | 30 min |
| **Weekly** | Answer one question in r/devops, r/cybersecurity, r/AppSec | Reddit | 30 min |
| **Bi-weekly** | Long-form post (architecture / accuracy / "Fendix vs X") | fendix.dev/blog → newsletter → HN/Lobste.rs | 4–6 hr |
| **Monthly** | Newsletter to email list — release notes + best wild finding of the month + roadmap | Buttondown / ConvertKit | 2 hr |
| **Monthly** | Public scan of a different top-100 OSS project; write up findings | fendix.dev/blog | 4 hr (incl. responsible disclosure if needed) |
| **Quarterly** | Accuracy report — re-run the full `scripts/accuracy/run.py` + `scripts/heavy-eval/run.py` on the new release, publish numbers | fendix.dev/accuracy | 1 day |

### 6.2 Comparison content (the SEO play)

These pages drive long-tail traffic from people Googling "X alternative" or "X vs Y":

| Page | Target search | Angle |
|---|---|---|
| `/vs/semgrep` | "fendix vs semgrep" / "semgrep alternative" | Same SAST surface + DAST correlation; not a replacement, a layer above |
| `/vs/snyk` | "snyk alternative free" / "snyk vs open source" | Comparable dep-CVE coverage, no SaaS, no per-seat pricing |
| `/vs/zap` | "zap alternative" / "zap vs burp" | Lighter-weight, CI-native, single binary |
| `/vs/bandit` | "bandit vs semgrep" | Bandit + Semgrep + taint chains + DAST in one tool |
| `/vs/dependabot` | "dependabot alternative for vulnerabilities" | Reachability via govulncheck, not just version diff |

Write 3 in Phase 0/1, the other 2 in weeks 5–8. Each ~1000 words, honest about where the competitor wins.

### 6.3 Community rituals

- **Hacktoberfest (October)** — Tag 15+ issues with `hacktoberfest`. Curate. Merge fast.
- **Discord server (Discord is free)** — Don't spin up unless GitHub Discussions overflows. Premature community = empty channels.
- **OWASP local chapter talks** — Free. DM the local chapter organizers. One 30-min talk per quarter.
- **Conference CFPs** — Submit to: DevSecCon (June/Sept windows), KubeCon EU (deadline ~Jan), GoCon EU (Sept). Even rejection emails surface your work to organizers who track DevTools.
- **Podcast pitches** — Changelog, Go Time (now bi-monthly), Software Engineering Daily, Practical AI, oxide.computer's. Friday after launch + every 6 weeks.

### 6.4 Newsletter list growth

Target: **1000 subscribers by Day 90**. Sources, ranked by realistic conversion:

1. Landing-page modal (lazy-fired after 30s) — ~60% of signups
2. README footer link — ~20%
3. Footer of every blog post — ~10%
4. End of every Show HN follow-up post ("get future scan write-ups by email") — ~10%
5. Twitter bio link — negligible but free

Send pattern: monthly long, one "tip / wild finding" short between sends. Two emails/month. Never more.

---

## 7. SaaS funnel prep (parallel track for weeks 4–12)

The point of the email list is to validate SaaS demand before you build the backend. Concrete actions:

| Week | Action |
|---|---|
| 4 | Add a one-question survey to the welcome email: "What's your AppSec pain right now?" |
| 6 | Send first "interview ask": 15 free signups → 5 calls → understand what they'd pay for |
| 8 | If 3+ calls converge on the same pain → write a one-page SaaS spec |
| 10 | Soft-launch "design partner" CTA in the newsletter — capped at 10 logos |
| 12 | Decide: build the SaaS, or pivot the backend roadmap |

**Hard rule:** don't promise features in the SaaS until 5+ paying-intent signals exist. The OSS reputation depends on shipping what you announce.

---

## 8. KPIs and review cadence

### 8.1 KPI targets (these are realistic for a solo OSS launch with zero budget — adjust if you have warm channels)

| Metric | Day 1 (launch) | Day 7 | Day 30 | Day 90 |
|---|---:|---:|---:|---:|
| HN ranking peak | #1–10 | — | — | — |
| GitHub stars | 300 | 800 | 1500 | 3000 |
| Email signups | 50 | 150 | 400 | 1000 |
| GitHub installs (unique IPs via release downloads or App installs) | — | 50 | 250 | 1000 |
| External blog/podcast mentions | — | 3 | 8 | 20 |
| GitHub Discussions started by non-you users | — | 5 | 25 | 80 |
| Marketplace App installs | — | 10 | 50 | 200 |
| Production users named publicly (logo wall) | — | 0 | 2 | 5 |
| SaaS design-partner calls completed | — | 0 | 1 | 5 |

### 8.2 Anti-KPIs (track but don't optimize)

- Vanity stars from unrelated trending lists
- Twitter follower count
- Press release pickups
- Conference attendees you don't talk to

### 8.3 Weekly review (15 min, every Monday)

```
1. Which channel produced the most signups/stars last week?
2. Which planned action did I drop? Add or kill.
3. What's the single biggest unblock for the SaaS funnel?
```

---

## 9. Tooling stack (all free)

| Purpose | Tool | Cost |
|---|---|---|
| Landing page hosting | GitHub Pages | Free |
| Email | Buttondown free tier (100 subs) → ConvertKit free (1000 subs) | Free → Free |
| Analytics | GoatCounter (OSS) or Plausible (free for 30k pageviews trial) | Free |
| Demo GIFs | [asciinema](https://asciinema.org) + `agg` to MP4 | Free |
| Image / OG card | Figma / Canva | Free |
| Scheduling tweets | Typefully free tier | Free |
| Newsletter discovery | [Console.dev](https://console.dev), [BetaList](https://betalist.com) — free submission | Free |
| Crash / install telemetry | **None** — README promises zero telemetry; respect that | Free |

Budget creep red flag: if you find yourself needing >$200/month for tools by Day 90, you're over-engineering. Re-read §1.

---

## 10. Failure modes — pre-mortems

| Scenario | Symptom | Plan B |
|---|---|---|
| HN post flops | < 50 upvotes in first 2 hr | Don't repost. Treat launch as soft-launch, lean into Phase 2 cadence harder. Re-launch as "Show HN: Six months of Fendix — here's what I learned" at month 6 |
| Reddit ban-hammer | Post removed in r/programming for self-promotion rules | r/programming is strict. Skip it; double down on r/devops + r/netsec |
| "Just use semgrep" pile-on | Comments dismiss the wedge | Have ready: 2-paragraph response with specific findings semgrep misses (correlation, dep-CVE call-graph). Pin it. |
| Accuracy claim attacked | Someone runs the harness, gets different number | Acknowledge immediately, file a bug, fix in next release. **Do not defend bad numbers.** This is the #1 brand-damage risk. |
| Critical security bug found post-launch | Someone reports an issue in the scanner itself | Pre-write a `SECURITY.md` disclosure flow (already exists — verify it's current). Pin the fix release prominently. |
| Burnout at week 6 | Cadence slips → silence → "looks abandoned" | Drop the weekly tweet first. Keep the bi-weekly post + monthly newsletter. Better to under-promise the cadence than to vanish. |

---

## 11. Decisions I need from you before executing

| # | Decision | Default if you don't decide | Deadline |
|---|---|---|---|
| 1 | Confirm "Option B" headline numbers (0.987 F1 / 1.000 recall / 44/44 real-world) — or have me tune the harness for 1.000 | Option B (honest, defensible) | End of Week 1 |
| 2 | Launch week (which Tuesday)? | Tuesday of Week 3 of this plan | Week 1 |
| 3 | Email tool: Buttondown vs ConvertKit | Buttondown (simpler, OSS-friendly) | Week 1 |
| 4 | Public fendix.dev landing page design — minimalist HTML, or use a template (e.g. [tabler.io free](https://tabler.io))? | Minimalist hand-rolled HTML (you control it; matches the brand) | Week 1 |
| 5 | Twitter/X or Mastodon as the primary microblogging channel? | X (still where DevTool audience lives in 2026) | Week 2 |
| 6 | Schedule for the SaaS / `fendix-backend` repo making it public — same week as engine, or held back? | Hold back. OSS engine launch first; SaaS announcement at Day 60 | Week 1 |

---

## 12. What I'll do next if you greenlight this

1. Open a `marketing-plan` GitHub issue from this doc with checkboxes for the Phase 0 prereq list
2. Refresh [launch-post.md](launch-post.md) to v0.15 numbers (Option B headline)
3. Sketch the `fendix.dev` landing page in a single HTML file
4. Draft the GitHub Discussions seed posts
5. Set up Buttondown + an embeddable signup form
6. Draft the 3 pre-launch blog posts (architecture / "what we scanned" / "no LLM")
7. Block out the launch-week calendar with hour-level slots

Estimated solo effort to ship Phase 0: **35–45 hours over 2 weeks** (so feasible as evenings + weekends if you have a day job, or 1 focused week if not).
