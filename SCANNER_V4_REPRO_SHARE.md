# Scanner V4 vuln-load — reproduce C2 & S2 (share sheet)

Compact hand-off for reproducing the slow initial vuln load and the two importer
speedups. Full detail: `SCANNER_V4_REPRO.md`, `SCANNER_V4_BUNDLE_LOAD_PERF.md`,
`SCANNER_V4_LOAD_FIX_PLAN.md`.

## Run it (one command)

```bash
curl -fSLo reproduce.sh \
  https://raw.githubusercontent.com/sthadka/stackrox/sthadka/scanner-v4-repro/scanner/hack/bundleload/reproduce.sh
chmod +x reproduce.sh

SMOKE=1 ./reproduce.sh   # ~2 min  — pipeline + correctness check only (tiny alpine feed)
QUICK=1 ./reproduce.sh   # ~45 min — rhel-vex only; representative C2/S2 gains
./reproduce.sh           # >1 h    — full 13-feed bundle
```

It clones `sthadka/stackrox@sthadka/scanner-v4-repro` (S1+S2 + harness) and
`sthadka/claircore@copy-bulk-vuln-load` (C2), downloads the public bundle, starts a
throwaway Postgres, and runs four configs into fresh DBs (dropped+recreated before
each run):

| config | claircore write path | JSON decode |
|---|---|---|
| baseline | per-row `INSERT`+`SELECT` | serial |
| c2 | COPY + set-based staging (#2033) | serial |
| s2 | per-row | parallel (`WORKERS`, default 4) |
| both | COPY + set-based staging | parallel |

Output: `$WORKDIR/REPORT.md` (default `WORKDIR=/tmp/sv4-repro`) with **wall time +
speedup, client CPU & max RSS, Go peak heap, peak Postgres memory, per-feed times,
and a row-count parity table**; raw logs in `$WORKDIR/logs/`.

## Requirements
`bash`, `git`, **go ≥ 1.26**, `docker` (or `CONTAINER_ENGINE=podman`), `curl`,
`unzip`, `python3`, GNU `/usr/bin/time` (optional), ~20 GB free disk.

## Knobs
`SMOKE=1` (alpine) · `QUICK=1` (rhel-vex) · `FEEDS=a,b` · `WORKERS=N` ·
`FILTER=1` (also enable the S1 not-affected filter) · `PPROF=1` (per-run CPU
profiles → `logs/<cfg>.pprof`) · `PGPORT` · `WORKDIR` · `CONTAINER_ENGINE`.

## Reading the numbers
- **Gains scale with feed size + alias density.** Small feeds (alpine has *no*
  aliases) show little/noisy improvement — that's why `SMOKE` is only a sanity check.
  C2's alias-callback-chain elimination shows up on rhel-vex (~8M alias rows).
- **Co-located DB understates C2.** Round-trips are ~free locally; C2's win is much
  larger against a **remote** DB (the environment that actually fails).
- **C2 trades some memory for speed** (bounded): it buffers one batch of rows
  (`CLAIRCORE_COPY_BATCH`, default 10k) and uses `TEMP` staging + set-based inserts,
  so client heap and Postgres peak rise modestly vs the per-row path. The **S1
  filter** (`FILTER=1`) cuts total volume ~37%, which more than offsets it.
- **S2 raises transient heap** (parallel decoders produce garbage faster) — it's
  opt-in for that reason.

## Data to share (all non-sensitive)
`reproduce.sh` (or the branch), your `REPORT.md` + `logs/*`, and — for byte-identical
numbers — your exact `bundle/vulnerabilities.zip` (the public URL refreshes daily).

## The PRs
- C2 — quay/claircore **#2033** (COPY write path)
- S1 — stackrox **#22919** (not-affected filter)
- S2 — stackrox **#22920** (parallel decode, stacked on #22919)
- M1 — memory guard already in tree (`ROX_MEMLIMIT` + `pkg/memlimit`)
