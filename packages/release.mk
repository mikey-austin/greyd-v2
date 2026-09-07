#
# packages/release.mk - packaging, release and coverage targets.
#
# Included from the top-level Makefile, whose variables (PACKAGE, VERSION,
# PROGRAMS, BINDIR, GO, MAKE, CONF_FILES, UNIT_FILES, MAN8, MAN5, ...) it
# relies on. Targets:
#
#   make packages     build deb and rpm packages into dist/ with nfpm
#   make pkg-stage    stage the package contents (configuration, units,
#                     manual pages) for nfpm and goreleaser
#   make release-check      validate .goreleaser.yaml
#   make release-snapshot   local goreleaser dry run into dist/
#   make coverage     unit tests with coverage, per-package totals and a
#                     COVER_MIN threshold (same check as CI)
#   make coverage-html      coverage.html from the last profile
#

NFPM        ?= nfpm
GORELEASER  ?= goreleaser
DISTDIR     ?= dist
PKG_FORMATS ?= deb rpm
PKG_STAGE   ?= packages/nfpm/stage
PKG_ARCH    ?= $(shell $(GO) env GOARCH)

# Programs shipped in the packages. Defaults to everything the Makefile
# builds; when greyd-monitor lands it only needs adding to PROGRAMS (or,
# to package a subset, listing the programs here).
PKG_PROGRAMS ?= $(PROGRAMS)

# Paths compiled into the packaged programs and substituted into the
# shipped configuration and units. They follow packages/rpm/greyd.spec.in
# and INSTALL ("Users and directories"): state in /var/lib/greyd, pidfiles
# under /var/empty. packages/nfpm/stage.sh and .goreleaser.yaml carry the
# same values; PKG_MAKEVARS is exported so stage.sh picks up any override
# made here.
PKG_prefix        ?= /usr
PKG_sysconfdir    ?= /etc
PKG_localstatedir ?= /var/lib
PKG_unitdir       ?= /usr/lib/systemd/system
PKG_MAKEVARS      ?= prefix=$(PKG_prefix) sysconfdir=$(PKG_sysconfdir) \
                     localstatedir=$(PKG_localstatedir) unitdir=$(PKG_unitdir) \
                     DEFAULT_CONFIG=$(PKG_sysconfdir)/$(PACKAGE)/greyd.conf \
                     GREYD_PIDFILE=/var/empty/greyd/greyd.pid \
                     GREYLOGD_PIDFILE=/var/empty/greylogd/greylogd.pid
export PKG_MAKEVARS

NFPM_CONFIG := packages/nfpm/nfpm.yaml

.PHONY: packages pkg-stage pkg-build pkg-clean release-check release-snapshot \
        coverage coverage-html

# Configuration, units, manual pages and documents, generated with the
# package paths (a recursive make so that the paths take effect).
pkg-stage:
	sh packages/nfpm/stage.sh $(PKG_STAGE)

# The programs with the package paths compiled in, built into the stage
# rather than $(BINDIR) so that a plain "make" is not left with binaries
# that expect /etc/greyd. The program targets are phony, so they always
# rebuild.
pkg-build: pkg-stage
	$(MAKE) $(PKG_PROGRAMS) BINDIR=$(PKG_STAGE)/sbin $(PKG_MAKEVARS)

packages: pkg-build
	@if ! command -v $(NFPM) >/dev/null 2>&1; then \
	    echo "nfpm is not installed; install it with one of:" >&2; \
	    echo "    $(GO) install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest" >&2; \
	    echo "    (or a package from https://nfpm.goreleaser.com/install/)" >&2; \
	    echo "and rerun make packages, or set NFPM=/path/to/nfpm" >&2; \
	    exit 1; \
	fi
	@mkdir -p $(DISTDIR)
	@set -e; for f in $(PKG_FORMATS); do \
	    VERSION=$(VERSION) GOARCH=$(PKG_ARCH) \
	        $(NFPM) package -f $(NFPM_CONFIG) -p $$f -t $(DISTDIR)/; \
	done
	@ls -1 $(DISTDIR)/$(PACKAGE)[-_]$(VERSION)* 2>/dev/null || true

pkg-clean:
	rm -rf $(PKG_STAGE)

# goreleaser (https://goreleaser.com); the GitHub release workflow in
# .github/workflows/release.yml runs the same configuration on tags.
release-check:
	@if ! command -v $(GORELEASER) >/dev/null 2>&1; then \
	    echo "goreleaser is not installed; see https://goreleaser.com/install/" >&2; exit 1; fi
	$(GORELEASER) check

release-snapshot:
	@if ! command -v $(GORELEASER) >/dev/null 2>&1; then \
	    echo "goreleaser is not installed; see https://goreleaser.com/install/" >&2; exit 1; fi
	$(GORELEASER) release --snapshot --clean --skip=publish,sign,sbom

#
# Coverage. The threshold and the commands mirror
# .github/workflows/coverage.yml; the profile is coverage.out (gitignored).
#
COVER_MIN     ?= 50
COVERPROFILE  ?= coverage.out

# -coverpkg attributes statements to the package they live in (so shared
# code exercised by another package's tests counts); the generated ANTLR
# parser and the conformance helpers are left out of the total.
coverage:
	CGO_ENABLED=0 $(GO) test -coverprofile=$(COVERPROFILE).raw -covermode=atomic -coverpkg=./... ./...
	grep -v -e '/internal/config/grammar/' -e '/adapters/db/dbtest/' $(COVERPROFILE).raw > $(COVERPROFILE)
	@echo "per-package statement coverage:"
	@awk 'NR > 1 && !($$1 in seen) { seen[$$1] = 1; \
	    split($$1, a, ":"); p = a[1]; sub(/\/[^\/]*$$/, "", p); pkg[$$1] = p; n[$$1] = $$2 } \
	    NR > 1 && $$3 > 0 { hit[$$1] = 1 } \
	    END { for (b in seen) { stmts[pkg[b]] += n[b]; if (hit[b]) cov[pkg[b]] += n[b] } \
	          for (p in stmts) printf "  %6.1f%%  %s\n", 100 * cov[p] / stmts[p], p }' \
	    $(COVERPROFILE) | sort -k2
	@total=$$($(GO) tool cover -func=$(COVERPROFILE) | tail -1 | awk '{ print $$NF }' | tr -d %); \
	echo "total: $$total% (minimum $(COVER_MIN)%)"; \
	awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { if (t + 0 < m + 0) { \
	    printf "coverage %.1f%% is below the %d%% minimum\n", t, m; exit 1 } }'

coverage-html: $(COVERPROFILE)
	$(GO) tool cover -html=$(COVERPROFILE) -o coverage.html
	@echo "wrote coverage.html"
