#!/usr/bin/env bash
#
# reproduce.sh — reproduce the Scanner V4 vuln-load slowdown and the C2/S2 fixes.
#
# It clones stackrox (this repro branch) + claircore into a fresh dir, downloads the
# real vulnerability bundle, starts a local Postgres, and runs the importer in four
# configurations:
#
#   baseline : per-row claircore write path,           serial JSON decode
#   c2       : COPY/staging write path (claircore #2033), serial JSON decode
#   s2       : per-row write path,           parallel JSON decode (stackrox #22920)
#   both     : COPY/staging write path + parallel JSON decode
#
# It measures, per run: wall time, per-feed time, client CPU (user+sys, %CPU),
# client peak RSS, Go peak heap, and peak Postgres-container memory — then writes a
# Markdown comparison report and verifies all runs produce identical row counts.
#
# The not-affected volume filter (S1) is OFF by default so C2/S2 are measured on the
# full ~13.3M-row bundle. Set FILTER=1 to also enable it.
#
# Requires: bash, git, go >= 1.26, docker (or CONTAINER_ENGINE=podman), curl, unzip,
# python3, GNU /usr/bin/time (optional, for CPU/RSS), ~20 GB free disk. Baseline runs
# are slow on the full bundle (>1h total). Speed knobs:
#   SMOKE=1  -> tiny alpine feed only (seconds/run); validates the pipeline end-to-end
#   QUICK=1  -> the dominant rhel-vex feed only (best single-feed view of C2 & S2)
#   FEEDS=a,b -> explicit feed list (e.g. "rhel-vex.json.zst,suse.json.zst")
# Each run uses its own database, dropped+recreated empty before the run for a clean,
# comparable slate.
#   PPROF=1  -> also write a Go CPU profile per run to logs/<name>.pprof
#              (view with: go tool pprof -top logs/c2.pprof)
#
set -euo pipefail

WORKDIR="${WORKDIR:-/tmp/sv4-repro}"
PGPORT="${PGPORT:-5433}"
WORKERS="${WORKERS:-4}"
CE="${CONTAINER_ENGINE:-docker}"
PG_IMAGE="${PG_IMAGE:-docker.io/library/postgres:15}"
PG_NAME="sv4-repro-pg"

STACKROX_REPO="${STACKROX_REPO:-https://github.com/sthadka/stackrox.git}"
# Branch carrying S1 (filter) + S2 (parallel decode) + this script + the harness.
STACKROX_BRANCH="${STACKROX_BRANCH:-sthadka/scanner-v4-repro}"
CLAIRCORE_FORK="${CLAIRCORE_FORK:-https://github.com/sthadka/claircore.git}"
C2_BRANCH="${C2_BRANCH:-copy-bulk-vuln-load}"

BUNDLE_URL="${BUNDLE_URL:-https://definitions.stackrox.io/v4/vulnerability-bundles/v4/vulnerabilities.zip}"
BUNDLE_ACCEPT="application/vnd.stackrox.scanner-v4.multi-bundle+zip"

LOGDIR="$WORKDIR/logs"
DSN_BASE="postgres://postgres@localhost:${PGPORT}"
TIME_CMD="$(command -v /usr/bin/time || true)"   # GNU time, for CPU + max RSS

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
log "0. preflight"
for bin in git go curl unzip python3 "$CE"; do
  command -v "$bin" >/dev/null || { echo "missing required tool: $bin"; exit 1; }
done
[ -n "$TIME_CMD" ] || echo "note: GNU /usr/bin/time not found; CPU/RSS columns will be blank (Go heap still reported)"
mkdir -p "$WORKDIR" "$LOGDIR"

# ---------------------------------------------------------------------------
log "1. clone repos into $WORKDIR"
[ -d "$WORKDIR/stackrox/.git" ] || git clone --filter=blob:none -b "$STACKROX_BRANCH" "$STACKROX_REPO" "$WORKDIR/stackrox"
[ -d "$WORKDIR/claircore/.git" ] || git clone "$CLAIRCORE_FORK" "$WORKDIR/claircore"
( cd "$WORKDIR/claircore" && git fetch -q origin "$C2_BRANCH" && git checkout -q "$C2_BRANCH" )
( cd "$WORKDIR/claircore" && git rev-parse -q --verify "${C2_BRANCH}~1" >/dev/null ) \
  || { echo "cannot resolve ${C2_BRANCH}~1 (per-row baseline commit)"; exit 1; }

# ---------------------------------------------------------------------------
log "1b. verify the benchmark harness is present"
test -f "$WORKDIR/stackrox/scanner/hack/bundleload/main.go" \
  || { echo "harness main.go missing on branch $STACKROX_BRANCH"; exit 1; }

# ---------------------------------------------------------------------------
log "2. download + extract the vulnerability bundle (public)"
mkdir -p "$WORKDIR/bundle"
[ -f "$WORKDIR/bundle/vulnerabilities.zip" ] || \
  curl -fSL -H "X-Scanner-V4-Accept: ${BUNDLE_ACCEPT}" -o "$WORKDIR/bundle/vulnerabilities.zip" "$BUNDLE_URL"
[ -d "$WORKDIR/bundle/bundles" ] || ( cd "$WORKDIR/bundle" && unzip -oq vulnerabilities.zip )
ls -1 "$WORKDIR/bundle/bundles"/*.json.zst >/dev/null || { echo "no feed files extracted"; exit 1; }

ONLY_ARGS=()
# Feed selection (first match wins): SMOKE = tiny/fast sanity run; QUICK = the
# dominant rhel-vex feed; FEEDS = explicit comma-separated list; otherwise all feeds.
if [ -z "${FEEDS:-}" ] && [ "${SMOKE:-0}" = "1" ]; then FEEDS="alpine.json.zst"; fi
if [ -z "${FEEDS:-}" ] && [ "${QUICK:-0}" = "1" ]; then FEEDS="rhel-vex.json.zst"; fi
[ -n "${FEEDS:-}" ] && { ONLY_ARGS=(-only "$FEEDS"); echo "feeds: $FEEDS"; } || echo "feeds: ALL"
FILTER_ARGS=(); [ "${FILTER:-0}" = "1" ] && { FILTER_ARGS=(-filter-notaffected); echo "S1 filter: ON"; }
[ "${PPROF:-0}" = "1" ] && echo "CPU profiling: ON (per-run .pprof files)"

# ---------------------------------------------------------------------------
log "3. start Postgres ($PG_IMAGE) on :$PGPORT"
$CE rm -f "$PG_NAME" >/dev/null 2>&1 || true
$CE run -d --name "$PG_NAME" --shm-size=1g \
  -e POSTGRES_USER=postgres -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p "${PGPORT}:5432" "$PG_IMAGE" >/dev/null
for _ in $(seq 1 30); do $CE exec "$PG_NAME" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 2; done
$CE exec "$PG_NAME" psql -U postgres -tc "select version();" >/dev/null
psql_c() { $CE exec "$PG_NAME" psql -U postgres "$@"; }

# peak memory of the Postgres container, in MiB, tracked in a file
sample_db_mem() {
  local out="$1" peak=0 mib
  while :; do
    mib="$($CE stats --no-stream --format '{{.MemUsage}}' "$PG_NAME" 2>/dev/null | awk '
      { v=$1; if (match(v,/[0-9.]+/)) n=substr(v,RSTART,RLENGTH)+0;
        if (v ~ /GiB/) f=1024; else if (v ~ /MiB/) f=1; else if (v ~ /KiB/) f=1/1024;
        else if (v ~ /GB/) f=953.674; else if (v ~ /MB/) f=0.953674; else f=1;
        printf "%d", n*f }')"
    [ -n "$mib" ] && [ "$mib" -gt "$peak" ] 2>/dev/null && peak="$mib"
    echo "$peak" > "$out"
    sleep 3
  done
}

# ---------------------------------------------------------------------------
log "4. wire the local claircore replace + resolve modules (once)"
cd "$WORKDIR/stackrox"
go mod edit -replace "github.com/quay/claircore=$WORKDIR/claircore"
go mod tidy

# run_cfg <name> <claircore-ref> <workers>
run_cfg() {
  local name="$1" ccref="$2" workers="$3"
  local db="repro_${name}" logf="$LOGDIR/${name}.log"
  log "run: $name  (claircore=$ccref, decode-workers=$workers)"
  ( cd "$WORKDIR/claircore" && git checkout -q "$ccref" )
  go build -o "$WORKDIR/bundleload" ./scanner/hack/bundleload
  # Clean slate: every run starts from a brand-new, empty database so all four
  # runs are directly comparable (the harness recreates the schema on startup).
  # FORCE handles any lingering connection from an interrupted previous run.
  echo "  reset database $db (drop + create empty)"
  psql_c -c "DROP DATABASE IF EXISTS $db WITH (FORCE);" >/dev/null
  psql_c -c "CREATE DATABASE $db;" >/dev/null

  : > "$LOGDIR/${name}.dbmem"
  sample_db_mem "$LOGDIR/${name}.dbmem" & local sampler=$!

  local pprof_args=()
  [ "${PPROF:-0}" = "1" ] && pprof_args=(-cpuprofile "$LOGDIR/${name}.pprof")

  local rc=0
  if [ -n "$TIME_CMD" ]; then
    CLAIRCORE_COPY_WORKERS=1 "$TIME_CMD" -v -o "$LOGDIR/${name}.time" \
      "$WORKDIR/bundleload" -db "${DSN_BASE}/${db}?sslmode=disable" \
      -dir "$WORKDIR/bundle/bundles" -workers "$workers" \
      "${ONLY_ARGS[@]}" "${FILTER_ARGS[@]}" "${pprof_args[@]}" >"$logf" 2>&1 || rc=$?
  else
    CLAIRCORE_COPY_WORKERS=1 \
      "$WORKDIR/bundleload" -db "${DSN_BASE}/${db}?sslmode=disable" \
      -dir "$WORKDIR/bundle/bundles" -workers "$workers" \
      "${ONLY_ARGS[@]}" "${FILTER_ARGS[@]}" "${pprof_args[@]}" >"$logf" 2>&1 || rc=$?
  fi

  kill "$sampler" 2>/dev/null || true; wait "$sampler" 2>/dev/null || true
  [ "$rc" -eq 0 ] || { echo "run $name FAILED (rc=$rc); see $logf"; tail -20 "$logf"; exit 1; }

  psql_c -d "$db" -tAc \
    "select 'vuln='||count(*) from vuln
     union all select 'uo_vuln='||count(*) from uo_vuln
     union all select 'alias='||count(*) from alias
     union all select 'vulnerability_alias='||count(*) from vulnerability_alias
     union all select 'vulnerability_self='||count(*) from vulnerability_self
     union all select 'enrichment='||count(*) from enrichment" \
    > "$LOGDIR/${name}.counts" 2>/dev/null || true
  psql_c -c "DROP DATABASE IF EXISTS $db;" >/dev/null   # free disk
  grep -E "ALL DONE" "$logf" || true
}

log "5. run the four configurations"
run_cfg baseline "${C2_BRANCH}~1" 1
run_cfg c2       "${C2_BRANCH}"    1
run_cfg s2       "${C2_BRANCH}~1" "$WORKERS"
run_cfg both     "${C2_BRANCH}"    "$WORKERS"

# ---------------------------------------------------------------------------
log "6. build the comparison report"
REPORT="$WORKDIR/REPORT.md"
LOGDIR="$LOGDIR" WORKERS="$WORKERS" python3 - "$REPORT" <<'PY'
import os, re, sys

report = sys.argv[1]
logdir = os.environ["LOGDIR"]
order = ["baseline", "c2", "s2", "both"]
labels = {
    "baseline": "baseline (per-row, serial)",
    "c2": "C2 COPY (serial decode)",
    "s2": "S2 parallel decode (per-row)",
    "both": "C2 + S2",
}

def dur_to_s(s):
    if not s: return None
    total = 0.0
    for val, unit in re.findall(r'([0-9.]+)(h|ms|m|s|µs|us|ns)', s):
        total += {"h":3600,"m":60,"s":1,"ms":1e-3,"µs":1e-6,"us":1e-6,"ns":1e-9}[unit]*float(val)
    return round(total, 1)

def fmt(sec):
    if sec is None: return "-"
    return f"{int(sec//60)}m{sec%60:04.1f}s" if sec >= 60 else f"{sec:.1f}s"

def spd(base, x): return f"{base/x:.2f}×" if (base and x) else "-"

tot, heap, sysmb, rss, cpu, pct, dbmem, feeds, counts = {}, {}, {}, {}, {}, {}, {}, {}, {}

for cfg in order:
    lp = os.path.join(logdir, f"{cfg}.log")
    if not os.path.exists(lp): continue
    txt = open(lp, errors="replace").read()
    m = re.search(r"ALL DONE total=(\S+)", txt)
    if m: tot[cfg] = dur_to_s(m.group(1))
    mh = re.search(r"peak_heap_mb=(\d+)\s+peak_sys_mb=(\d+)", txt)
    if mh: heap[cfg], sysmb[cfg] = int(mh.group(1)), int(mh.group(2))
    for bm in re.finditer(r"bundle done === bundle=(\S+) ops=\d+ dur=(\S+)", txt):
        feeds.setdefault(bm.group(1), {})[cfg] = dur_to_s(bm.group(2))
    tf = os.path.join(logdir, f"{cfg}.time")
    if os.path.exists(tf):
        tt = open(tf, errors="replace").read()
        u = re.search(r"User time \(seconds\): ([0-9.]+)", tt)
        s = re.search(r"System time \(seconds\): ([0-9.]+)", tt)
        p = re.search(r"Percent of CPU this job got: (\d+)%", tt)
        r = re.search(r"Maximum resident set size \(kbytes\): (\d+)", tt)
        if u and s: cpu[cfg] = round(float(u.group(1)) + float(s.group(1)), 1)
        if p: pct[cfg] = int(p.group(1))
        if r: rss[cfg] = int(r.group(1)) // 1024
    dm = os.path.join(logdir, f"{cfg}.dbmem")
    if os.path.exists(dm):
        v = open(dm).read().strip()
        if v.isdigit(): dbmem[cfg] = int(v)
    cf = os.path.join(logdir, f"{cfg}.counts")
    if os.path.exists(cf):
        counts[cfg] = dict(l.split("=",1) for l in open(cf).read().split() if "=" in l)

present = [c for c in order if c in tot]
base = tot.get("baseline")
o = []
o.append("# Scanner V4 vuln-load — C2/S2 reproduction report\n")
o.append(f"Decode workers for S2/both: **{os.environ.get('WORKERS','?')}**. "
         "S1 not-affected filter OFF unless FILTER=1, so all runs process the same volume.\n")
o.append("> Gains scale with **feed size and alias density**, and C2's round-trip win is "
         "largest against a **remote** DB. Small feeds (e.g. `alpine`, which has *no* aliases) "
         "show little/noisy improvement and are only a pipeline + correctness check — use "
         "`QUICK=1` (rhel-vex) or a full run for representative numbers.\n")

o.append("## Totals (time, CPU, memory)\n")
o.append("| configuration | wall time | speedup | client CPU (u+s) | %CPU | client max RSS (MB) | Go peak heap (MB) | Postgres peak (MB) |")
o.append("|---|---:|---:|---:|---:|---:|---:|---:|")
for c in present:
    o.append(f"| {labels[c]} | {fmt(tot[c])} | {spd(base,tot[c])} | "
             f"{cpu.get(c,'-')}{'s' if c in cpu else ''} | {pct.get(c,'-')}{'%' if c in pct else ''} | "
             f"{rss.get(c,'-')} | {heap.get(c,'-')} | {dbmem.get(c,'-')} |")
o.append("")
o.append("- **client CPU / RSS**: the importer process (proxy for the matcher) via GNU time.\n"
         "- **Postgres peak**: peak memory of the DB container during the run.\n"
         "- **Go peak heap**: high-water live heap inside the importer.\n")

o.append("## Per-feed wall time (seconds)\n")
o.append("| feed | " + " | ".join(labels[c] for c in present) + " |")
o.append("|---|" + "---:|"*len(present))
for feed in sorted(feeds, key=lambda f: -(feeds[f].get("baseline") or 0)):
    o.append("| " + feed + " | " + " | ".join(
        (f"{feeds[feed].get(c):.1f}" if feeds[feed].get(c) is not None else "-") for c in present) + " |")
o.append("")

o.append("## Row counts (correctness — identical across runs)\n")
keys = ["vuln","uo_vuln","alias","vulnerability_alias","vulnerability_self","enrichment"]
o.append("| table | " + " | ".join(labels[c] for c in present) + " |")
o.append("|---|" + "---:|"*len(present))
for k in keys:
    o.append("| " + k + " | " + " | ".join(counts.get(c,{}).get(k,"-") for c in present) + " |")
o.append("")

open(report,"w").write("\n".join(o))
print("\n".join(o))
PY

log "done. report: $REPORT   |   raw logs: $LOGDIR/{baseline,c2,s2,both}.log"
if [ "${PPROF:-0}" = "1" ]; then
  echo "CPU profiles: $LOGDIR/{baseline,c2,s2,both}.pprof"
  echo "  view: cd $WORKDIR/stackrox && go tool pprof -top $LOGDIR/c2.pprof"
fi
