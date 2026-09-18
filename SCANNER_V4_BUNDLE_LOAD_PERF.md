# Scanner V4 Vulnerability Bundle Load — Performance Investigation

**Status:** in progress (living document; updated at checkpoints)
**Goal:** the initial Scanner V4 vulnerability load takes 45–90 min in the field.
Bring it down to "a few minutes."

---

## TL;DR

- The initial load's cost was **not** WAL/fsync, disk, or data volume — it was the
  ClairCore matcher store issuing **tens of millions of individual round-trip-bound
  SQL statements** (per-vuln `INSERT`+`SELECT`, and a per-alias
  `INSERT`/`SELECT`/associate callback chain smeared across two connections).
- Rewriting that path to **COPY into per-transaction staging tables + a handful of
  set-based `INSERT ... SELECT` statements** removes the DB as the bottleneck.
- After the rewrite the load is **CPU-bound on single-threaded JSON decode +
  hashing** on the matcher side. Next lever: **process feeds/records concurrently**
  (one of the user's suggestions).

---

## Test environment

- Box: 4 vCPU, 15 GB RAM. **Postgres runs on the same box as the client**, so
  client (JSON decode) and server (INSERT execution) contend for the same 4 cores.
  In production the DB is a separate pod/host, so absolute numbers differ, but the
  *relative* wins and the bottleneck analysis hold.
- Postgres 15 (container), `pg_stat_statements` enabled. Config tuning
  (`synchronous_commit=off`, `max_wal_size=8GB`) was measured and had **negligible
  effect** (67s → 65s on the ubuntu bundle) — confirming the load is CPU-bound, not
  WAL-bound.
- Real production bundle: `definitions.stackrox.io/v4/vulnerability-bundles/v4/vulnerabilities.zip`
  (multi-bundle zip, 262 MB compressed, **~32 GB decompressed JSON**, 13 bundles).
- Harness: `scanner/hack/bundleload` — a throwaway tool that mirrors the production
  import path (`jsonblob.Iterate` → `store.UpdateVulnerabilitiesIter` /
  `UpdateEnrichmentsIter`), minus HTTP fetch / locking / scheduling, so a single
  bundle or a directory of bundles can be timed against a local Postgres.

## Data volume (full load)

| table                | rows   |
|----------------------|--------|
| vuln                 | 13.3M  |
| uo_vuln              | 13.3M  |
| vulnerability_alias  | 8.2M   |
| vulnerability_self   | 8.8M   |
| alias                | 620K   |
| enrichment           | 776K   |

The single `rhel-vex` bundle is **one update operation with 8.9M vulnerability
records** and heavy aliases — it dominates everything.

---

## Root cause (baseline profiling)

The write path is ClairCore's `(*MatcherStore).updateVulnerabilities`
(`datastore/postgres/updatevulnerabilities.go`). Per **vulnerability** it issued:

- `INSERT INTO vuln (...30 cols...) ON CONFLICT (hash_kind,hash) DO NOTHING`
- `SELECT id FROM vuln WHERE hash_kind=$1 AND hash=$2` (needed because
  `ON CONFLICT DO NOTHING` + `RETURNING` returns nothing on conflict)
- `INSERT INTO uo_vuln (uo,vuln) ... ON CONFLICT DO NOTHING`

Per **alias** (and the "self" alias) it additionally issued an
`INSERT alias_namespace` / `INSERT alias` / `SELECT alias.id` / `INSERT pivot`
chain, wired together with `pgx.Batch` **callbacks across two connections** (the
alias batch was deliberately run outside the transaction so the main tx could see
it at READ COMMITTED).

`pg_stat_statements` for the full baseline load (server-side exec time ≈ 18.7 min
of the 27.5 min wall; the rest is client-side JSON + pipeline round-trip waits):

| query | calls | total | % |
|---|---:|---:|---:|
| INSERT INTO vuln | 15.3M | 407s | 36% |
| INSERT INTO uo_vuln | 15.3M | 168s | 15% |
| INSERT INTO alias | 19.0M | 83s | 7% |
| INSERT INTO vulnerability_self | 10.2M | 70s | 6% |
| INSERT INTO vulnerability_alias | 9.2M | 66s | 6% |
| SELECT alias.id | 19.4M | 58s | 5% |
| FK trigger checks (uo_vuln→uo, →vuln) | 44M | 80s | 7% |
| SELECT id FROM vuln (by hash) | 15.3M | 26s | 2% |

Live inspection during the dominant `rhel-vex` operation showed only ~1.5 of 4
cores busy: the callback-chained batches (insert → get vuln id → insert alias →
get alias id → associate) create **round-trip dependencies**, so the client spends
most of its time waiting on the network rather than doing work. That is why
`rhel-vex` alone took **16m14s**.

---

## Checkpoint 1 — COPY + set-based staging rewrite

**Change (in ClairCore, `datastore/postgres/updatevulnerabilities.go`):** replace
the per-row insert loop and the per-alias callback chain with, per ~50k-row batch:

1. `COPY` staged rows into two per-transaction `TEMP` tables (`tmp_vuln`,
   `tmp_alias`, both `ON COMMIT DROP`).
2. `INSERT INTO vuln SELECT ... FROM tmp_vuln ON CONFLICT DO NOTHING`
3. `INSERT INTO uo_vuln SELECT $uo, v.id FROM vuln v JOIN tmp_vuln ...`
4. `INSERT INTO alias_namespace / alias SELECT DISTINCT ...`
5. `INSERT INTO vulnerability_alias / vulnerability_self SELECT ... JOIN ...`
6. `TRUNCATE` the staging tables and repeat.

Row ids are recovered by **joining on the unique keys** (`vuln(hash_kind,hash)`,
`alias(namespace,name)`) instead of a per-row `SELECT`, so the extra select and the
whole callback chain disappear. Everything now happens **inside one transaction on
one connection** (the second connection is gone). Memory stays bounded (~320 MB
during the 8.9M-row `rhel-vex` op) because rows are buffered per batch, not for the
whole operation.

**Correctness:** verified identical output on the alias-rich `osv` bundle — old vs
new produce byte-identical row counts:
`vuln=870862, uo_vuln=870862, alias=541898, vulnerability_alias=249661, vulnerability_self=870862`.

**Results (same box, single bundle, into an empty DB):**

| bundle | records | old (per-row) | new (COPY) | speedup |
|---|---:|---:|---:|---:|
| osv | 870K | 88s | 60s | 1.5× |
| rhel-vex | 8.9M | 16m14s | 11m30s | 1.4× |

The DB is no longer the bottleneck. During the new `rhel-vex` run the client sits
at ~106% CPU (one core, JSON decode + md5 hashing) while Postgres is largely idle
waiting for the next batch — i.e. we shifted from **round-trip-bound** to
**single-thread-CPU-bound**. That is exactly the regime where feed/record
concurrency pays off.

### Old comments — are they all addressed?

The old code carried several "why" comments; each is accounted for:

- *"isolation level must be pinned to READ COMMITTED … to see alias rows committed
  outside this transaction"* — no longer true: aliases are now written **inside**
  the transaction via staging, so there is no cross-connection visibility
  requirement. Comment updated to say we keep READ COMMITTED only as a stable,
  explicit default.
- *"batches are chains of statements smeared across two connections … callback
  hell … MUST be sent in this order … aliasBatch MUST be sent outside the
  transaction"* — the two-connection callback chain is deleted. Ordering is now
  explicit and linear (insert vuln → associate → namespaces → aliases → pivots),
  all on one connection/transaction.
- *"INSERT … RETURNING only works if an insertion happened"* (the reason for the
  separate per-row `SELECT`) — obsolete: ids are resolved set-wise by joining on
  the unique keys, so no `RETURNING` and no per-row `SELECT` are needed.
- *"SeenSpace tracks alias namespaces to avoid redundant namespace creation"* —
  replaced by `INSERT ... SELECT DISTINCT namespace ... ON CONFLICT DO NOTHING`.
- *"the Vulnerability isn't pinned in memory until the batch is processed"* — still
  honored: we copy only the needed field values into the batch buffer and never
  retain `*claircore.Vulnerability`; memory is bounded by the batch size.

---

## Checkpoint 2 — feed-level concurrency (and why feeds are NOT independent)

**Idea:** process N bundles concurrently (≈ one per CPU) in the bundle loop.

**Key finding — feeds are *not* fully independent.** They write to the same
global, content-deduplicated tables (`vuln`, `alias`, `alias_namespace`): the same
CVE alias (`CVE-2024-…`) appears in nvd, osv, debian, ubuntu, rhel-vex, etc.
Concurrent `INSERT … ON CONFLICT DO NOTHING` on those shared keys contend, and
Postgres aborts one transaction as a **deadlock victim** (`SQLSTATE 40P01`). We hit
this immediately when a small feed ran concurrently with `rhel-vex`.

**Root of the contention:** an uncommitted unique-index entry blocks any other
transaction trying to insert the same key until the first transaction commits.
`rhel-vex` is one ~11 min transaction that touches most CVE alias keys, so while it
runs it blocks (and deadlocks) other feeds on those shared keys. The one-big-
transaction-per-operation model turns "independent feeds" into contending ones.

**Measured:** the 12 non-`rhel-vex` feeds run concurrently at `conc=4` in
**6m10s** with **no deadlock** (their transactions are short, so shared-key
blocking windows are brief). The deadlock only appeared once the long `rhel-vex`
transaction overlapped another feed.

**Conclusion:** feed concurrency is safe/useful *among the short feeds*, but not
while `rhel-vex` is running. So it cannot, by itself, get us under `rhel-vex`'s
duration — `rhel-vex` must get faster.

## Checkpoint 3 — intra-feed concurrency (parallel JSON) + faster decoder

The bundle is **newline-delimited JSON** (one record per line; JSON escapes any
in-value newline), so lines can be split cheaply and serially, and the expensive
per-record `json.Unmarshal` fanned out to a worker pool. **This does not break
linearity:** within an operation the datastore stores a deduplicated *set*
(`ON CONFLICT` + set-based inserts), so record order is irrelevant.

Implemented `jsonblob.IterateParallel(r, workers, unmarshal)` — a drop-in for the
existing `iterateFunc`, so the production `Import` loop is unchanged. A serial
reader splits lines and detects operation boundaries (cheap `"Ref"` scan); worker
goroutines unmarshal; a single consumer yields the results to the datastore.

**JSON decoder:** we use the standard library `encoding/json`, which the profile
shows dominates client CPU (`encoding/json.object` ≈ 44% of samples; md5 is only
~2%). Faster drop-ins already in the module graph: **`goccy/go-json`** (respects
the custom `UnmarshalJSON`/`UnmarshalText` methods claircore needs) and
`json-iterator/go`. `encoding/json/v2` exists in the Go 1.26 toolchain but is
`GOEXPERIMENT`-gated. The decoder is pluggable via the `-json` flag.

**Results (rhel-vex, 8.9M records):**

| config | time | vs per-row baseline |
|---|---:|---:|
| per-row (original) | 16m14s | 1.0× |
| COPY, serial | 11m30s | 1.4× |
| COPY, workers=4 | 9m07s | 1.8× |

**Why only 1.25× from parallel unmarshal here (not ~4×):** once unmarshal is
offloaded, the **serial consumer** becomes the bottleneck — claircore's md5 +
row-building + pgx COPY binary-encoding + the batch DB flushes all run on one
goroutine, and the workers throttle to its pace via backpressure. On this box that
consumer, the unmarshal workers, *and* Postgres share the same 4 cores
(oversubscription). In production the DB is a separate host with its own cores and
the co-located contention disappears, so both the COPY win and the parallel-decode
win should be larger than measured here.

**Correctness:** the parallel path produces byte-identical row counts to the serial
path on the alias-rich `osv` bundle.

---

## Where the remaining time goes (and how to get to minutes)

Ordered by expected impact on this workload:

1. **Move md5 + row-building into the unmarshal workers.** They already hold the
   decoded vulnerability; having them also compute the hash and build the COPY row
   removes that work from the serial consumer, leaving it to do only COPY +
   set-based inserts. (Requires threading a "pre-built row" type from the parallel
   iterator into a small claircore bulk API.)
2. **Parallelize the COPY itself.** The last serial piece is pgx binary-encoding
   the COPY stream on one connection. Sharding a single operation across several
   connections (each COPY-ing into its own staging table, one final set-based
   merge) parallelizes it — at the cost of the operation no longer being a single
   transaction (acceptable for the idempotent initial load, but a real semantic
   change).
3. **Schedule feeds to exploit safe concurrency:** run the short feeds with feed
   concurrency, and give `rhel-vex` intra-feed workers, rather than running
   everything one way.
4. **Faster JSON decoder** (`goccy/go-json`) — composes with all of the above.

---

## Checkpoint 5 — the biggest lever: skip not-affected records ACS never uses

Profiling and the incident notes converged on the same thing: **volume**. The Red
Hat VEX feed emits a "known not affected" (`Invert`) record for every
product/package a CVE does *not* affect. Counting the real bundle:

| rhel-vex records | count |
|---|---:|
| total | 8,907,410 |
| not-affected (`Invert`) | 5,002,937 |
| &nbsp;&nbsp;… on **ancestry** (RHCC/container) packages — **ACS uses these** | 103,842 |
| &nbsp;&nbsp;… on **non-ancestry** (RPM) packages — **ACS never uses these** | **4,899,095** |

**ACS only consults not-affected assertions for Ancestry/RHCC packages** — the only
matcher that reads `Invert` records is `rhel/rhcc/matcher.go`, and it matches
Ancestry packages against container repositories. A not-affected record for a
non-Ancestry (RPM) package is dead weight: written, indexed, but never matched.

So **55% of rhel-vex is unused rows.** Claircore's exporter already drops them
(`rhel/vex` parser: `if st.PURL.Type == packageurl.TypeRPM { continue }`, PR
#2027), but the **currently-served production bundle still contains them**. Adding
the same filter on the **import** side captures the win immediately (and defends
against any future bundle that reincludes them):

```go
// scanner/matcher/updater/vuln/filter.go
func ignoreVulnerability(v *claircore.Vulnerability) bool {
	return v.Invert && (v.Package == nil || v.Package.Kind != types.AncestryPackage)
}
```
Gated by `ROX_SCANNER_V4_SKIP_UNUSED_NOT_AFFECTED` (default on), applied in the
importer's `Import` loop before records reach the datastore.

**Result (rhel-vex, this box):**

| config | records imported | time | peak heap |
|---|---:|---:|---:|
| COPY, serial (no filter) | 8.9M | 11m30s | — |
| COPY, workers=4 (no filter) | 8.9M | 9m07s | — |
| COPY, workers=4, **filter** | **4.0M** | **4m06s** | **134 MB** |

**Correctness:** the DB keeps exactly the 103,842 not-affected *ancestry* records
ACS uses and drops all 4,899,095 non-ancestry ones — verified by querying
`vuln` (`not_vulnerable AND package_kind<>'ancestry'` = 0).

## Checkpoint 6 — memory (OOM is the release-blocking failure mode)

The matcher has been OOMing in CI (bumped 4Gi→6Gi and still failing), so the
parallel pipeline must not inflate peak heap. Two things keep it bounded:

- **Small, fixed buffers.** The datastore write is the throughput bottleneck, so
  letting decode/build workers race ahead only piles decoded records in memory for
  no speedup. Channel buffers are `O(workers)`, not tens of thousands; the COPY
  batch size is configurable (`CLAIRCORE_COPY_BATCH`, default 20k, down from 50k)
  and worker count is capped (`min(GOMAXPROCS,4)`, `CLAIRCORE_COPY_WORKERS`).
- **The filter** removes ~4.9M records from the largest feed before they are
  decoded into long-lived buffers or written.

**Measured peak Go heap (single feed, into an empty DB):**

| path | osv | notes |
|---|---:|---|
| old per-row, serial | 28 MB | tiny per-batch buffer (pgx.Batch≈1000) |
| new COPY, serial | ~101 MB | buffers one COPY batch (`copyBatchLim`) |
| new COPY, serial, batch=10k | lower | default lowered 20k→10k for headroom |

The COPY rewrite trades a little heap (one batch of buffered rows) for far fewer
round-trips — an explicit memory-for-speed trade, kept bounded and configurable.

**Two things keep the *matcher process* safe from OOM:**

1. **Production uses serial unmarshal.** The parallel `IterateParallel` decoder is
   opt-in (used by the benchmark harness); the production `Import` path keeps the
   serial `jsonblob.Iterate`, so production peak is the ~100 MB-class single-batch
   profile, **not** the harness's higher parallel-decode figure (parallel workers
   generate decoded-record garbage faster, raising transient heap).
2. **The filter cuts total volume 37%** (rhel-vex −55%), which is the real OOM
   root cause — fewer records decoded, buffered, and written.

**Recommended matcher deploy setting:** set **`GOMEMLIMIT`** to ~90% of the
container memory limit. It is the standard Go soft-limit that makes the GC work
harder as it approaches the cap, which is the durable guard against the OOM-kills
seen in CI — complementary to the code changes here.

> Note on the two OOM sites: the **matcher/importer** OOM is driven by the number
> of live decoded objects + GC pressure across the ~13.3M-row load — attacked by the
> filter + bounded buffers + `GOMEMLIMIT`. The **exporter/bundler** OOM (~8.8 GB,
> bundle generation, `scanner/updater/export.go`) is a different code path, but it
> shares the *same volume root cause*: filtering the unused not-affected rows **at
> the exporter** (claircore `rhel/vex`, PR #2027) shrinks what the exporter holds
> *and* the bundle every importer downloads. That is why the durable filter belongs
> in claircore's exporter, with the scanner importer filter as an immediate/defensive
> complement. See `SCANNER_V4_LOAD_FIX_PLAN.md` for the claircore-vs-scanner split.

## Checkpoint 4 — full load, end to end

Full production bundle (13 feeds, ~32 GB decompressed JSON), same box, into an
empty DB:

| configuration | vuln rows | total time | peak heap | vs baseline |
|---|---:|---:|---:|---:|
| original (per-row, serial, no filter) | 13.3M | **27m31s** | — | 1.0× |
| COPY + parallel decode (no filter) | 13.3M | 17m59s | — | 1.53× |
| **COPY + filter (production default: serial decode)** | **8.76M** | **16m12s** | **529 MB** | **1.70×** |
| **COPY + filter + parallel decode (opt-in)** | **8.76M** | **12m11s** | **654 MB** | **2.26×** |

The **production-default** row (serial decode) is the honest, memory-lean number to
ship; parallel decode is the opt-in upside. Per-feed with the full stack:
`rhel-vex` 16m14s→**4m06s** (parallel) / **6m52s** (serial), `suse`
5m39s→**3m34s**, `ubuntu` 1m50s→**~1m**.

> On a *remote* production DB these ratios should be larger: the original's cost is
> dominated by ~50M network round-trips (nearly free here on a local socket), and
> COPY collapses those into a handful of batched statements.

**Correctness:** the filtered run keeps every affected record and every
not-affected *ancestry* record ACS uses, dropping only the unused non-ancestry
not-affected rows (`vuln`=8,762,059; `not_vulnerable AND package_kind<>'ancestry'`
= 0; `enrichment`=776,367 unchanged). With the filter *disabled* the output is
byte-identical to the original for every table.

**Read the numbers in context.** This box runs the client and Postgres on the same
4 cores, so the COPY round-trip win is understated (round-trips are ~free locally)
and the parallel win is capped by CPU oversubscription. Against a **remote**
production DB the COPY rewrite should help substantially more; the filter and
memory wins are environment-independent.

## Where the bottleneck moved (a tour of the levers)

Each lever exposed the next bottleneck — a useful map of the pipeline:

1. **per-row round-trips** (original) → COPY rewrite →
2. **client JSON unmarshal** (single-thread) → parallel decode →
3. **client row-building / COPY-encode** (single-thread) → parallel build →
4. **single-connection DB write** (index maintenance + FK checks on one backend) →
   … addressable only by connection-sharding (breaks single-tx atomicity) or
   index-deferral (measured ~9% for rhel-vex — not worth the complexity).

The **not-affected filter** sidesteps (4) for the worst feed by not doing the work
at all — which is why it is the single biggest win and should be prioritised.

## Summary of changes

- **ClairCore `datastore/postgres/updatevulnerabilities.go`** — rewrote the insert
  path from per-row `INSERT`+`SELECT` + two-connection alias callback chain to
  `COPY` into per-transaction staging tables + set-based `INSERT … SELECT`, with an
  optional parallel row-building worker pool (`CLAIRCORE_COPY_WORKERS`,
  `CLAIRCORE_COPY_BATCH`). Bounded buffers. Stale comments updated.
- **`scanner/matcher/updater/vuln/filter.go`** (new) — `ignoreVulnerability`, the
  not-affected volume filter, gated by `ROX_SCANNER_V4_SKIP_UNUSED_NOT_AFFECTED`
  (default on); wired into `Import`.
- **`scanner/updater/jsonblob/parallel.go`** (new) — `IterateParallel`, a drop-in
  parallel-unmarshal iterator with a pluggable decoder (stdlib / goccy).
- **`scanner/hack/bundleload/`** (new, throwaway) — the benchmark harness.
- **`go.mod`** — `replace github.com/quay/claircore => /home/ec2-user/work/claircore`
  for local iteration (revert before merging; land the ClairCore change in the fork
  and cut a version — note the local claircore already includes PR #2027, so these
  numbers are additive to what is already shipping).

## Landing plan / open items

1. **Filter first.** It is the biggest, safest, environment-independent win and
   directly cuts the OOM/volume root cause. Land the import-side filter; the
   exporter already filters (#2027) so the two converge.
2. **COPY rewrite** into the claircore fork; bump ACS off the `replace`.
3. **Validate on a remote DB** (separate host, realistic PVC/IOPS) — that is the
   environment actually failing, and where COPY should shine. Use the new
   load-time metric (PR #22890 → BigQuery).
4. **Then** peel back the CI masking bumps (6Gi, 2h readiness, 3h test).
5. Re-baseline once the volume-filtered bundle ships so the filter win is not
   double-counted.

## Reproduction

```
# start a local postgres (see AGENTS.md) on :5433, then:
go build -o /tmp/bundleload ./scanner/hack/bundleload
/tmp/bundleload -db 'postgres://postgres@localhost:5433/bench?sslmode=disable' -dir /tmp/bundles
```

Local ClairCore is wired via `go.mod`:
`replace github.com/quay/claircore => /home/ec2-user/work/claircore`.
