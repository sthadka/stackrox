// Command bundleload is a throwaway benchmark harness to measure how long it
// takes to import Scanner V4 vulnerability bundles into Postgres.
//
// It mirrors the production import path (scanner/matcher/updater/vuln.Import ->
// store.UpdateVulnerabilitiesIter / UpdateEnrichmentsIter) but strips away the
// HTTP fetch, locking, and scheduling so we can point it at a local bundle file
// and a local Postgres and time the DB writes in isolation.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/toolkit/types"
	"github.com/stackrox/rox/scanner/datastore/postgres"
	"github.com/stackrox/rox/scanner/updater/jsonblob"
)

func main() {
	var (
		dsn        = flag.String("db", "postgres://postgres@localhost:5433/postgres?sslmode=disable", "postgres connection string")
		bundle     = flag.String("bundle", "", "path to a single decompressed .json or .json.zst bundle file")
		zipDir     = flag.String("dir", "", "directory of .json.zst bundle files to import in order (alternative to -bundle)")
		only       = flag.String("only", "", "comma-separated basename filter when using -dir (e.g. ubuntu.json.zst)")
		nostore    = flag.Bool("nostore", false, "decode/unmarshal records but do NOT write to the DB (isolates client-side JSON cost)")
		conc       = flag.Int("conc", 1, "number of bundles to import concurrently (feed-level parallelism)")
		workers    = flag.Int("workers", 1, "number of JSON-unmarshal workers per feed (intra-feed parallelism); 1 = serial")
		jsonlib    = flag.String("json", "std", "JSON decoder: std | goccy")
		filterNA   = flag.Bool("filter-notaffected", false, "skip not-affected records ACS never uses (Invert && non-ancestry)")
		cpuprofile = flag.String("cpuprofile", "", "write a CPU profile to this file")
	)
	flag.Parse()

	unmarshal := jsonblob.StdUnmarshal
	if *jsonlib == "goccy" {
		unmarshal = jsonblob.GoccyUnmarshal
	}

	if *cpuprofile != "" {
		pf, err := os.Create(*cpuprofile)
		must(err)
		must(pprof.StartCPUProfile(pf))
		defer pprof.StopCPUProfile()
	}

	slog.SetLogLoggerLevel(slog.LevelDebug)
	ctx := context.Background()

	pool, err := postgres.Connect(ctx, *dsn, "bundleload")
	must(err)
	defer pool.Close()

	store, err := postgres.InitPostgresMatcherStore(ctx, pool, true)
	must(err)

	var files []string
	switch {
	case *bundle != "":
		files = []string{*bundle}
	case *zipDir != "":
		entries, err := os.ReadDir(*zipDir)
		must(err)
		for _, e := range entries {
			if filepath.Ext(e.Name()) == ".zst" {
				if *only != "" && !contains(*only, e.Name()) {
					continue
				}
				files = append(files, filepath.Join(*zipDir, e.Name()))
			}
		}
	default:
		fmt.Println("must provide -bundle or -dir")
		os.Exit(2)
	}

	// Peak-heap sampler: OOM is the failure mode we care about, so track the
	// high-water mark of Go's live heap and total process memory reservation.
	var peakHeap, peakSys uint64
	stopMem := make(chan struct{})
	var memWG sync.WaitGroup
	memWG.Add(1)
	go func() {
		defer memWG.Done()
		var ms runtime.MemStats
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stopMem:
				return
			case <-t.C:
				runtime.ReadMemStats(&ms)
				if ms.HeapAlloc > peakHeap {
					peakHeap = ms.HeapAlloc
				}
				if ms.Sys > peakSys {
					peakSys = ms.Sys
				}
			}
		}
	}()

	grandStart := time.Now()
	sem := make(chan struct{}, *conc)
	var wg sync.WaitGroup
	for _, f := range files {
		sem <- struct{}{}
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()
			importFile(ctx, store, path, *nostore, *workers, unmarshal, *filterNA)
		}(f)
	}
	wg.Wait()
	close(stopMem)
	memWG.Wait()
	slog.Info("ALL DONE", "total", time.Since(grandStart).String(), "files", len(files),
		"conc", *conc, "workers", *workers, "json", *jsonlib, "nostore", *nostore,
		"peak_heap_mb", peakHeap/(1<<20), "peak_sys_mb", peakSys/(1<<20))
}

func ignoreVuln(v *claircore.Vulnerability) bool {
	return v != nil && v.Invert && (v.Package == nil || v.Package.Kind != types.AncestryPackage)
}

func importFile(ctx context.Context, store postgres.MatcherStore, path string, nostore bool, workers int, unmarshal jsonblob.UnmarshalFunc, filterNA bool) {
	f, err := os.Open(path)
	must(err)
	defer f.Close()

	var r io.Reader = f
	if filepath.Ext(path) == ".zst" {
		dec, err := zstd.NewReader(f)
		must(err)
		defer dec.Close()
		r = dec
	}

	name := filepath.Base(path)
	start := time.Now()
	slog.Info("=== importing bundle ===", "bundle", name)

	iter, iterErr := jsonblob.IterateParallel(r, workers, unmarshal)
	var opCount int
	iter(func(op *driver.UpdateOperation, it jsonblob.RecordIter) bool {
		opStart := time.Now()
		count := 0
		var ref uuid.UUID
		var err error
		if nostore {
			// Drain the record iterator so jsonblob performs the JSON
			// unmarshal for every record, but skip all DB writes. This
			// isolates the client-side decode/unmarshal cost.
			it(func(v *claircore.Vulnerability, e *driver.EnrichmentRecord) bool {
				count++
				_, _ = v, e
				return true
			})
			must(iterErr())
			opCount++
			slog.Info("op decoded (nostore)", "updater", op.Updater, "kind", string(op.Kind),
				"records", count, "dur", time.Since(opStart).String())
			return true
		}
		switch op.Kind {
		case driver.VulnerabilityKind:
			ref, err = store.UpdateVulnerabilitiesIter(ctx, op.Updater, op.Fingerprint, func(yield func(*claircore.Vulnerability, error) bool) {
				it(func(v *claircore.Vulnerability, _ *driver.EnrichmentRecord) bool {
					if filterNA && ignoreVuln(v) {
						return true
					}
					count++
					return yield(v, nil)
				})
				if err := iterErr(); err != nil {
					yield(nil, err)
				}
			})
		case driver.EnrichmentKind:
			ref, err = store.UpdateEnrichmentsIter(ctx, op.Updater, op.Fingerprint, func(yield func(*driver.EnrichmentRecord, error) bool) {
				it(func(_ *claircore.Vulnerability, e *driver.EnrichmentRecord) bool {
					count++
					return yield(e, nil)
				})
				if err := iterErr(); err != nil {
					yield(nil, err)
				}
			})
		default:
			slog.Warn("unknown kind", "kind", string(op.Kind))
			return true
		}
		must(err)
		opCount++
		d := time.Since(opStart)
		rate := float64(count) / d.Seconds()
		slog.Info("op imported", "updater", op.Updater, "kind", string(op.Kind),
			"records", count, "dur", d.String(), "rec_per_sec", fmt.Sprintf("%.0f", rate), "ref", ref.String())
		return true
	})
	must(iterErr())
	slog.Info("=== bundle done ===", "bundle", name, "ops", opCount, "dur", time.Since(start).String())
}

func contains(csv, name string) bool {
	for _, p := range splitCSV(csv) {
		if p == name {
			return true
		}
	}
	return false
}

func splitCSV(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func must(err error) {
	if err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}
