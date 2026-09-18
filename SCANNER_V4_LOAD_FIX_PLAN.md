# Scanner V4 vuln-load / OOM — remediation plan

**Companion to:** `SCANNER_V4_BUNDLE_LOAD_PERF.md` (measurements & investigation).
**Incident:** ROX-37055 / ROX-34109 — the Scanner V4 matcher OOMs / loads the vuln
bundle too slowly (45–90 min in the field), blocking the e2e readiness gate and the
ACS 5.0 release.

This document is the *plan*: what to change, **where (claircore vs scanner)**, why,
the expected benefit, and the order to do it in.

---

## Draft PRs (for ACS engineers to test & merge as they see fit)

All are **draft** and developed with AI assistance; treat them as starting points to
validate, not final. The scanner PRs are **stacked** (S2's base is S1's branch).

| ID | Change | PR | Status |
|---|---|---|---|
| C1 | Exporter: drop RPM `known_not_affected` | quay/claircore **#2027** (merged) | adopt via a claircore version bump |
| C2 | Importer write path: COPY + set-based staging | quay/claircore **#2033** (draft, from `sthadka/claircore:copy-bulk-vuln-load`) | needs review + a cut version |
| S1 | Importer: not-affected safety-net filter | stackrox **#22919** (draft) | ready to review |
| S2 | Importer: parallel + pluggable JSON decode | stackrox **#22920** (draft, stacked on #22919) | ready to review |
| M1 | Memory guards (`GOMEMLIMIT`/`ROX_MEMLIMIT`) | — **already in tree** (`pkg/memlimit` + matcher deployment) | verify sizing only |

**How to test the full stack together** (before a real claircore release exists):
in `stackrox` check out `sthadka/scanner-v4-parallel-decode` (gets S1+S2), then point
it at the C2 code with a temporary
`go mod edit -replace github.com/quay/claircore=<path-to-#2033-checkout>` +
`go mod tidy`. Set `ROX_SCANNER_V4_IMPORT_WORKERS=4` (and optionally
`ROX_SCANNER_V4_JSON_DECODER=goccy`, `CLAIRCORE_COPY_WORKERS=4`) to exercise the
parallel paths. `SCANNER_V4_BUNDLE_LOAD_PERF.md` has the benchmark harness
(`scanner/hack/bundleload`, not part of any PR) and reproduction steps.

> ⚠️ The `go mod replace` is **only** for local testing — it must not be committed.
> The real dependency is a claircore release containing #2027 (and later #2033).

---

## 1. There are two failure sites, one root cause

| site | code path | symptom |
|---|---|---|
| **Importer / matcher** | `scanner/updater/jsonblob` → claircore `datastore/postgres` | initial load OOMs / exceeds readiness deadline |
| **Exporter / bundler** | `scanner/updater/export.go` → claircore `rhel/vex` + `libvuln/jsonblob` | bundle *generation* OOMs (~8.8 GB, ~25 min) in CI |

**Root cause (both):** volume. The Red Hat VEX migration + kernel advisories grew
the set from ~9M → **13.3M** rows; `rhel-vex` alone is a single **8.9M-record**
update operation, of which **~4.9M (55%) are RPM `known_not_affected` records ACS
never uses**.

Because both sites share the volume root cause, **the highest-leverage fix
(dropping the unused rows) is most valuable at the source — the exporter (claircore)
— where it shrinks the bundle for every importer *and* cuts exporter memory.**

---

## 2. Where each change belongs, and why

| # | Change | Home | Why there | Fixes |
|---|---|---|---|---|
| 1 | **Drop RPM `known_not_affected`** | **claircore** `rhel/vex` (exporter) — *already in PR #2027* | Filtering at generation shrinks the bundle for all importers and cuts exporter heap. Fixing only in the importer leaves the exporter still building/holding 4.9M rows. | exporter **and** importer |
| 2 | **Importer safety-net filter** for the same rows | **scanner** `matcher/updater/vuln/filter.go` | Immediate benefit on the *currently served* bundle (which still contains the rows until the exporter ships), and a defense-in-depth guard if a future bundle reincludes them. ACS-specific policy → out-of-tree importer, not shared claircore. | importer (now) |
| 3 | **COPY + set-based staging write path** | **claircore** `datastore/postgres/updatevulnerabilities.go` | This is the shared datastore the ACS out-of-tree importer calls; the write path only exists here. Importer-only (exporter writes a file, not the DB). | importer |
| 4 | **Parallel JSON decode** (`IterateParallel`) | **scanner** `updater/jsonblob/parallel.go` | The out-of-tree importer owns bundle parsing; claircore's in-tree importer is not on ACS's path. | importer (opt-in) |
| 5 | **`GOMEMLIMIT` + bounded buffers** | **scanner** deploy (matcher pod & bundler job) + claircore buffer sizing | GC soft-limit is a deploy/runtime guard; buffer caps live with the code that allocates them. | both |

**One-line answer to "claircore or scanner?":** the **volume filter** is primarily
a **claircore (exporter)** fix — that is what also cures the bundler OOM — with a
**scanner (importer)** filter as the immediate/defensive complement. The **write-path
speedup** is **claircore (datastore)**. The **parallel decode** is **scanner**.

---

## 3. The changes in detail

### C1 — Exporter: drop unused not-affected rows (claircore, mostly done)
- **What:** claircore `rhel/vex` parser skips `known_not_affected` for RPM
  (`if st.PURL.Type == packageurl.TypeRPM { continue }`) — PR #2027, in
  `v1.6.1-0.20260916195820-3902930ff815`.
- **Benefit:** rhel-vex **8.9M → ~4.0M** records at the source; exporter heap
  ~8.8 GB → ~4.3 GB (measured in-thread); smaller bundle download for every matcher.
- **StackRox action:** **bump claircore off v1.6.0** to a release containing #2027.
  Confirm kernel advisories are retained (needed for 5.0.0).
- **Risk:** low — matching semantics unchanged (ACS only uses ancestry not-affected).
- **Effort:** version bump + regression run.

### S1 — Importer: safety-net filter (scanner — PR #22919)
- **What:** `ignoreVulnerability(v) = v.Invert && Package.Kind != AncestryPackage`,
  applied in `Import` before records reach the datastore. Gated by
  `ROX_SCANNER_V4_SKIP_UNUSED_NOT_AFFECTED` (default on).
- **Benefit:** removes **4,899,095** rows from `rhel-vex` on the *currently served*
  bundle → −55% rhel-vex, −37% total, immediately — without waiting for the exporter
  bundle to propagate. rhel-vex load 16m14s → 4–7 min; full load 27m → 12–16 min.
- **Correctness:** keeps all 103,842 ancestry not-affected records ACS uses; drops
  only the 4.9M non-ancestry ones (verified: `not_vulnerable AND kind<>'ancestry'` = 0).
- **Risk:** low, and reversible via the env flag.
- **Effort:** done (`filter.go` + one call site).

### C2 — Importer write path: COPY + set-based staging (claircore — PR #2033)
- **What:** replace per-row `INSERT`+`SELECT` and the two-connection per-alias
  callback chain with `COPY` into per-transaction TEMP staging tables + a handful of
  set-based `INSERT … SELECT` statements (ids resolved by joining on unique keys).
  Bounded batch (`CLAIRCORE_COPY_BATCH`, default 10k); optional parallel row-building
  is **default-off** (`CLAIRCORE_COPY_WORKERS`) because it reorders `vuln.id`s.
- **Benefit:** eliminates ~50M round-trip-bound statements. Local box: rhel-vex
  16m→11.5m; **much larger on a remote DB** where round-trips cost real latency
  (the actual failing environment). Also respects the DB `statement_timeout` (6m)
  because each batched statement is small.
- **Correctness:** passes claircore's integration suite (update / delta / enrichment
  / e2e); output byte-identical to the original.
- **Risk:** medium (core datastore rewrite) — mitigated by the passing integration
  tests and keeping the delta path intact. Land in the claircore fork + cut a version.
- **Effort:** done locally (needs to move from the `replace` into the fork).

### S2 — Importer parse: parallel JSON decode (scanner — PR #22920, opt-in)
- **What:** `jsonblob.IterateParallel(r, workers, decoder)` — a drop-in for the
  serial iterator that fans `json.Unmarshal` across workers (bundle is
  newline-delimited; order-independent because the store dedups to a set). Pluggable
  decoder (stdlib / `goccy/go-json`).
- **Benefit:** full load 16m12s → 12m11s locally (CPU-bound feeds); rhel-vex
  6m52s → 4m06s. Bigger on CPU-rich matcher nodes.
- **Cost:** more transient heap (parallel workers produce decoded-record garbage
  faster): local peak 529 MB → 654 MB.
- **Decision:** keep the production `Import` on **serial** decode by default (lower,
  more predictable heap given the OOM history); expose parallel as opt-in. Revisit
  once `GOMEMLIMIT` is in place.
- **Risk:** low (opt-in, order-independent for ACS).
- **Effort:** done; wiring into `Import` behind an env flag is a small follow-up.

### M1 — Memory guards (**already implemented** + bounded buffers in C2)
- **Status — the GOMEMLIMIT half already exists.** `scanner/cmd/scanner/main.go`
  calls `memlimit.SetMemoryLimit()`, and the matcher deployment
  (`image/templates/helm/shared/templates/02-scanner-v4-07-matcher-deployment.yaml`)
  sets `ROX_MEMLIMIT` from `requests.memory`; `pkg/memlimit` then sets the Go soft
  limit to 95% of it. In CI the matcher patch sets requests = limits = 6Gi, so the
  soft limit is already ≈ 5.7 GiB. **No new GOMEMLIMIT code/config is needed.**
- **What remains:** (a) the **bounded buffers** are part of C2 (`copyBatchLim` /
  `CLAIRCORE_COPY_BATCH`, `O(workers)` channels); (b) **verify sizing** —
  `ROX_MEMLIMIT` tracks `requests.memory`, so ensure requests are set on every
  flavor (audit `SCANNER_V4_DB_STORAGE_CLASS`/resource gaps), and once the volume
  filter lands, the 6Gi bump can likely be walked back.
- **Takeaway:** the durable memory win is **cutting the volume (C1/S1)**, not adding
  a memory limit that is already in place.
- **Risk / effort:** none for the mechanism; verification only.

---

## 4. Recommended order

Ordered by **leverage ÷ risk**, and by unblocking the release fastest.

1. **C1 — bump claircore to a #2027 release.**
   Biggest single win, at the source, fixes *both* OOM sites, lowest risk. Do first.
2. **S1 — land the importer safety-net filter.**
   Immediate benefit on the already-served bundle (before C1's bundle propagates) and
   permanent defense-in-depth. Small, safe, reversible.
   *(C1 + S1 together resolve the volume/OOM root cause.)*
3. **M1 — verify memory sizing (mechanism already in tree).** `ROX_MEMLIMIT` /
   `pkg/memlimit` already set the Go soft limit from `requests.memory`; just confirm
   requests are set on every flavor. No code change.
4. **C2 (#2033) — land the COPY/staging write path in claircore; bump ACS.**
   The durable load-time fix, especially on the remote/slow-PVC production DB.
   Land after (1) so it rides the same claircore version bump.
   **S2 (#22920)** — parallel decode — can land independently once its base (S1)
   merges; it is default-off, so it is safe to merge before tuning.
5. **Validate on a *remote* DB** (separate host, realistic PVC/IOPS) using the new
   load-time metric (PR #22890 → BigQuery). This is the environment that actually
   fails; confirm the numbers there, not just locally.
6. **S2 — optionally wire parallel decode into `Import`** behind an env flag, once
   `GOMEMLIMIT` is confirmed and if remote-DB numbers show decode is the bottleneck.
7. **Peel back the CI masking bumps** (6Gi → back down, 2h readiness, 3h test) only
   after 1–5 prove the load is fast + bounded. Gate vuln readiness only where suites
   need it.
8. **Longer-term:** matcher **partial-ready** mode (serve with scan-notes marking
   incomplete data) so a slow load degrades instead of hard-blocking — the fallback
   if perf alone can't meet the readiness budget.

---

## 5. Expected end state (local box; remote DB should be better)

| stage | rhel-vex | full load | matcher peak heap |
|---|---:|---:|---:|
| today (v1.6.0, per-row) | 16m14s | 27m31s | — |
| + C1/S1 filter | 6m52s | ~16m | 529 MB |
| + C2 COPY | (folded in above) | 16m12s | 529 MB |
| + S2 parallel decode (opt-in) | 4m06s | 12m11s | 654 MB |

Plus: exporter heap ~8.8 GB → ~4.3 GB (C1), and `GOMEMLIMIT` preventing OOM-kills
at both sites.

---

## 6. Validation & rollback

- **Correctness:** claircore integration suite (update/delta/enrichment/e2e) must
  stay green; assert final `vuln` counts and that
  `not_vulnerable AND package_kind<>'ancestry'` = 0 after a load; a full e2e scan
  smoke-test to confirm no matching regressions from the filter.
- **Rollback levers:** `ROX_SCANNER_V4_SKIP_UNUSED_NOT_AFFECTED=false` disables the
  importer filter; `CLAIRCORE_COPY_WORKERS`/`CLAIRCORE_COPY_BATCH` tune the write
  path; parallel decode stays opt-in. The claircore bump is revertible by version.
- **Must-do before merge:** remove the local `replace github.com/quay/claircore =>
  …` from `go.mod`; land C2 in the claircore fork and depend on a cut version.
