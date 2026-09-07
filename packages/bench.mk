#
# Benchmark regression checks (packages/bench). Included from the Makefile.
#
#   make bench                 run every benchmark several times into bench.txt
#   make bench-compare OLD=a NEW=b
#                              benchstat the two result files and fail on a
#                              significant slowdown above BENCH_MAX_SLOWDOWN
#
# CI (.github/workflows/bench.yml) compares each run with the results of
# the last successful run on main, kept as a workflow artifact; absolute
# numbers are not committed because they only mean something on one
# machine.
#
BENCH_COUNT        ?= 6
BENCH_TIME         ?= 300ms
BENCH_OUT          ?= bench.txt
BENCH_MAX_SLOWDOWN ?= 50
BENCHSTAT_VERSION  ?= latest

.PHONY: bench bench-compare bench-tools

bench:
	CGO_ENABLED=0 $(GO) test -run '^$$' -bench . -benchmem -count $(BENCH_COUNT) -benchtime $(BENCH_TIME) ./... | tee $(BENCH_OUT)

bench-tools:
	$(GO) install golang.org/x/perf/cmd/benchstat@$(BENCHSTAT_VERSION)

# benchstat prints a table; packages/bench/check.py parses its CSV output
# and fails when a benchmark's sec/op grew by more than BENCH_MAX_SLOWDOWN
# percent with a significant p-value.
bench-compare:
	@[ -n "$(OLD)" ] && [ -n "$(NEW)" ] || { echo "usage: make bench-compare OLD=old.txt NEW=new.txt"; exit 2; }
	@export PATH="$(GOBIN_DIR):$$PATH"; command -v benchstat >/dev/null 2>&1 || { echo "benchstat not installed; run: make bench-tools"; exit 2; }; \
	benchstat "$(OLD)" "$(NEW)"; \
	benchstat -format csv "$(OLD)" "$(NEW)" | python3 packages/bench/check.py --max-slowdown $(BENCH_MAX_SLOWDOWN)
