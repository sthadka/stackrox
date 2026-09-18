# Reproducing the Scanner V4 vuln-load slowdown and the C2/S2 fixes

This reproduces the slow initial vulnerability load and measures the two importer
speedups in isolation and together:

- **C2** — claircore COPY + set-based staging write path (PR quay/claircore #2033)
- **S2** — parallel, pluggable JSON decode in the ACS importer (PR stackrox #22920)

on the **real** production bundle, against a local Postgres, and emits a Markdown
report comparing four runs (**baseline / C2 / S2 / both**) with per-feed timings and
peak memory.

> The **S1** not-affected volume filter is a separate lever and is left **off** here
> so C2 and S2 are measured on the full ~13.3M-row bundle (apples-to-apples). Add
> `FILTER=1` to see it too. See `SCANNER_V4_LOAD_FIX_PLAN.md` for the full picture.

---

## TL;DR

The reproduction lives on a fork branch: **`sthadka/stackrox` @ `sthadka/scanner-v4-repro`**
(it also carries the S1+S2 code and the C2 change is pulled from
`sthadka/claircore` @ `copy-bulk-vuln-load`). Grab just the script — it clones
everything into a fresh dir itself:

```bash
curl -fSLo reproduce.sh \
  https://raw.githubusercontent.com/sthadka/stackrox/sthadka/scanner-v4-repro/scanner/hack/bundleload/reproduce.sh
chmod +x reproduce.sh

# fast, representative (rhel-vex feed only, ~15–30 min):
QUICK=1 ./reproduce.sh

# full bundle (all 13 feeds, can take >1h at baseline speeds):
./reproduce.sh

# results:
#   /tmp/sv4-repro/REPORT.md          <- comparison tables (time, CPU, memory, per-feed)
#   /tmp/sv4-repro/logs/*.log         <- raw per-feed timings for each run
#   /tmp/sv4-repro/logs/*.time        <- GNU time output (CPU + max RSS) per run
```

Requirements: `bash`, `git`, **go ≥ 1.26**, `docker` (or `CONTAINER_ENGINE=podman`),
`curl`, `unzip`, `python3`, GNU `/usr/bin/time` (optional, for CPU/RSS), ~20 GB disk.

---

## What the four runs are

The script pins the write path via which claircore commit it builds against, and the
decode path via a flag — everything else is identical:

| run | claircore write path | JSON decode |
|---|---|---|
| `baseline` | per-row `INSERT`+`SELECT` (commit before #2033) | serial |
| `c2` | COPY + set-based staging (#2033) | serial |
| `s2` | per-row | parallel (`-workers N`) |
| `both` | COPY + set-based staging | parallel |

`baseline` is exactly the commit **before** the COPY change (`copy-bulk-vuln-load~1`),
so the only difference between `baseline`↔`c2` (and `s2`↔`both`) is the write-path
change. The only difference between `baseline`↔`s2` (and `c2`↔`both`) is the decoder.

## The report

`REPORT.md` contains three tables:
1. **Totals** — total time, speedup vs baseline, peak heap / sys per run.
2. **Per-feed timings** — seconds per feed per run (this is the "data per feed").
3. **Row counts** — `vuln`/`uo_vuln`/`alias`/… per run; these must be **identical**
   across all four runs (proof the speedups don't change the result).

Raw per-feed lines are in `logs/<run>.log` (the harness logs `op imported … records=…
dur=… rec_per_sec=…` per updater and `bundle done … dur=…` per feed).

## Knobs

| env | default | meaning |
|---|---|---|
| `WORKDIR` | `/tmp/sv4-repro` | working dir (repos, bundle, logs, report) |
| `QUICK` | `0` | `1` → only the `rhel-vex` feed (fast, still shows C2 & S2) |
| `FEEDS` | *(all)* | comma-separated subset, e.g. `rhel-vex.json.zst,suse.json.zst` |
| `WORKERS` | `4` | parallel-decode workers for `s2`/`both` |
| `FILTER` | `0` | `1` → also enable the S1 not-affected filter in every run |
| `PGPORT` | `5433` | host port for the throwaway Postgres |
| `CONTAINER_ENGINE` | `docker` | set to `podman` if preferred |

---

## What data you can share (all non-sensitive)

Everything here is safe to share — the vulnerability data is public and the code is
already headed to PRs:

- **`reproduce.sh`** and the harness `scanner/hack/bundleload/` (on branch
  `sthadka/scanner-v4-repro`). Colleagues only strictly need `reproduce.sh`.
- **The exact bundle you tested**, if you want byte-identical numbers: the file
  `/tmp/sv4-repro/bundle/vulnerabilities.zip` (~262 MB). The public URL
  (`definitions.stackrox.io/v4/vulnerability-bundles/v4/vulnerabilities.zip`, sent
  with header `X-Scanner-V4-Accept: application/vnd.stackrox.scanner-v4.multi-bundle+zip`)
  is **refreshed continually**, so a fresh fetch will give slightly different counts
  — the *relative* comparison still holds, but share the zip for an exact repro.
- **Your results**: `REPORT.md` and `logs/*.log`.
- **The analysis docs**: `SCANNER_V4_BUNDLE_LOAD_PERF.md` (measurements) and
  `SCANNER_V4_LOAD_FIX_PLAN.md` (plan + PR list).

## Caveats / reading the numbers

- **Co-located DB understates C2.** If the script's Postgres runs on the same host,
  network round-trips are ~free, so C2's per-row-elimination win looks smaller than
  it will on a **remote** production DB (the environment that actually fails). To
  approximate production, point the script at a remote Postgres via `PGPORT`/DSN or
  add latency; C2 should widen there.
- **S2 needs spare CPU.** Parallel decode helps when decode is CPU-bound; on a
  DB-bound host its win is smaller. It also raises peak heap a little (report shows
  it) — that's why it is opt-in (`ROX_SCANNER_V4_IMPORT_WORKERS`).
- Each run uses its own database, dropped after its row counts are captured, so peak
  disk is ~one loaded DB (~8–10 GB) at a time.
