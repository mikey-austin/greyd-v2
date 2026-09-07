#
# greyd - greylisting & blacklisting daemon (Go port)
#
# Common targets:
#   make            build all programs into bin/
#   make test       vet + unit tests (make test-race adds the race detector)
#   make fuzz       run the fuzz targets for FUZZTIME (default 10s) each
#   make lint       vet + golangci-lint + govulncheck (each skipped if absent)
#   make tools      go install golangci-lint & govulncheck, fetch the ANTLR jar
#   make generate   regenerate the ANTLR configuration parser
#   make install    install programs, configuration, systemd units and man pages
#

PACKAGE        := greyd
VERSION        := 1.0.0
MODULE         := github.com/mikey-austin/greyd-golang

GO             ?= go
JAVA           ?= java
CURL           ?= /usr/bin/curl
INSTALL        ?= install
SED            ?= sed

prefix         ?= /usr/local
exec_prefix    ?= $(prefix)
sbindir        ?= $(exec_prefix)/sbin
sysconfdir     ?= $(prefix)/etc
localstatedir  ?= $(prefix)/var
datarootdir    ?= $(prefix)/share
mandir         ?= $(datarootdir)/man
docdir         ?= $(datarootdir)/doc/$(PACKAGE)
libdir         ?= $(exec_prefix)/lib
unitdir        ?= $(prefix)/lib/systemd/system
DESTDIR        ?=

DEFAULT_CONFIG    ?= $(sysconfdir)/$(PACKAGE)/greyd.conf
GREYD_PIDFILE     ?= $(localstatedir)/empty/greyd/greyd.pid
GREYLOGD_PIDFILE  ?= $(localstatedir)/empty/greylogd/greylogd.pid

# Directories holding the pidfiles; the systemd units need them writable.
GREYD_PIDDIR      := $(patsubst %/,%,$(dir $(GREYD_PIDFILE)))
GREYLOGD_PIDDIR   := $(patsubst %/,%,$(dir $(GREYLOGD_PIDFILE)))

PROGRAMS       := greyd greydb greyd-setup greylogd greyd-monitor
BINDIR         := bin

ANTLR_VERSION  := 4.13.1
ANTLR_JAR      := .tools/antlr-$(ANTLR_VERSION)-complete.jar
ANTLR_URL      := https://www.antlr.org/download/antlr-$(ANTLR_VERSION)-complete.jar
GRAMMAR_DIR    := internal/config/grammar
GRAMMAR        := $(GRAMMAR_DIR)/GreydConf.g4

# Lint tooling installed by "make tools" (into GOBIN, or GOPATH/bin).
GOLANGCI_LINT_VERSION := v2.5.0
GOVULNCHECK_VERSION   := latest
GOBIN_DIR       = $(or $(shell $(GO) env GOBIN),$(shell $(GO) env GOPATH)/bin)

VERSION_PKG    := $(MODULE)/internal/version
LDFLAGS        := -s -w \
                  -X '$(VERSION_PKG).Version=$(VERSION)' \
                  -X '$(VERSION_PKG).DefaultConfig=$(DEFAULT_CONFIG)' \
                  -X '$(VERSION_PKG).GreydPidfile=$(GREYD_PIDFILE)' \
                  -X '$(VERSION_PKG).GreylogdPidfile=$(GREYLOGD_PIDFILE)'

GOFLAGS        ?=
export CGO_ENABLED = 0

CONF_SUBST     := -e 's,[@]PACKAGE[@],$(PACKAGE),g' \
                  -e 's,[@]GREYD_PIDFILE[@],$(GREYD_PIDFILE),g' \
                  -e 's,[@]GREYLOGD_PIDFILE[@],$(GREYLOGD_PIDFILE),g' \
                  -e 's,[@]GREYD_PIDDIR[@],$(GREYD_PIDDIR),g' \
                  -e 's,[@]GREYLOGD_PIDDIR[@],$(GREYLOGD_PIDDIR),g' \
                  -e 's,[@]DEFAULT_CONFIG[@],$(DEFAULT_CONFIG),g' \
                  -e 's,[@]CURL[@],$(CURL),g' \
                  -e 's,[@]libdir[@],$(libdir),g' \
                  -e 's,[@]sbindir[@],$(sbindir),g' \
                  -e 's,[@]localstatedir[@],$(localstatedir),g' \
                  -e 's,[@]sysconfdir[@],$(sysconfdir),g'

CONF_FILES     := etc/greyd.conf etc/greyd.docker.conf etc/greyd.redhat-init \
                  etc/greylogd.redhat-init etc/greyd.debian-init etc/greylogd.debian-init

UNIT_DIR       := packages/systemd
UNIT_FILES     := $(UNIT_DIR)/greyd.service $(UNIT_DIR)/greylogd.service \
                  $(UNIT_DIR)/greyd-setup.service $(UNIT_DIR)/greyd-setup.timer \
                  $(UNIT_DIR)/greyd-monitor.service \
                  $(UNIT_DIR)/greyd.socket $(UNIT_DIR)/greyd-config.socket \
                  $(UNIT_DIR)/greyd-unprivileged.service

MAN8           := doc/greyd.8 doc/greylogd.8 doc/greydb.8 doc/greyd-setup.8 doc/greyd-monitor.8
MAN5           := doc/greyd.conf.5

.PHONY: all build $(PROGRAMS) generate test test-race test-db-docker fuzz lint fmt vet man \
        conf units install uninstall dist docker clean distclean tools

all: build

build: $(PROGRAMS)

$(PROGRAMS):
	@mkdir -p $(BINDIR)
	$(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/$@ ./cmd/$@

#
# Parser generation. The generated Go sources are committed, so this is only
# needed after editing the grammar.
#
$(ANTLR_JAR):
	@mkdir -p .tools
	$(CURL) -sSfL -o $@ $(ANTLR_URL)

# Developer tooling: the linters used by "make lint" plus the ANTLR jar.
tools: $(ANTLR_JAR)
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	@echo "installed into $(GOBIN_DIR); make lint finds them there or on PATH"

generate: $(ANTLR_JAR)
	$(JAVA) -jar $(ANTLR_JAR) -Dlanguage=Go -package grammar -no-visitor -listener \
	    -o $(GRAMMAR_DIR) -Xexact-output-dir $(GRAMMAR)
	$(GO) fmt ./$(GRAMMAR_DIR)/... >/dev/null

#
# Quality.
#
fmt:
	$(GO) fmt ./...

# The ANTLR generated parser contains unreachable statements by design.
vet:
	$(GO) vet -unreachable=false ./...

# Configuration lives in .golangci.yml. Missing tools are skipped, not errors.
lint: vet
	@export PATH="$(GOBIN_DIR):$$PATH"; \
	if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run ./...; \
	else echo "golangci-lint not installed; skipping (run: make tools)"; fi
	@export PATH="$(GOBIN_DIR):$$PATH"; \
	if command -v govulncheck >/dev/null 2>&1; then govulncheck ./...; \
	else echo "govulncheck not installed; skipping (run: make tools)"; fi

test: vet
	$(GO) test ./...

# Fuzz targets, run one at a time for FUZZTIME each (seed corpora also run
# under plain "make test").
FUZZTIME ?= 10s
FUZZ_TARGETS := internal/config/parse:FuzzString internal/spamdlist:FuzzParseLimited \
                internal/smtp:FuzzParseProxyHeader internal/smtp:FuzzExpandMessage \
                internal/sync:FuzzDecode internal/ipc:FuzzDecode internal/ipc:FuzzReader \
                adapters/db/kv:FuzzDecodeKey adapters/db/kv:FuzzDecodeData
fuzz:
	@set -e; for t in $(FUZZ_TARGETS); do \
	    pkg=$${t%%:*}; fn=$${t##*:}; \
	    echo "fuzz $$pkg $$fn ($(FUZZTIME))"; \
	    $(GO) test -run '^$$' -fuzz "^$$fn$$" -fuzztime $(FUZZTIME) ./$$pkg/; \
	done

# The race detector needs cgo; everything else is built without it.
test-race: vet
	CGO_ENABLED=1 $(GO) test -race ./...

# Runs the MySQL & PostgreSQL driver tests against throw-away containers.
test-db-docker:
	docker compose -f packages/docker/docker-compose.test.yml up -d --wait
	GREYD_TEST_MYSQL_DSN='greyd:greyd@tcp(127.0.0.1:13306)/greyd' \
	GREYD_TEST_POSTGRESQL_DSN='postgres://greyd:greyd@127.0.0.1:15432/greyd?sslmode=disable' \
	    $(GO) test -count=1 ./adapters/db/mysql/ ./adapters/db/postgresql/ ; \
	    status=$$?; docker compose -f packages/docker/docker-compose.test.yml down -v; exit $$status

#
# Documentation. The roff/html pages are committed; regenerate with ronn
# after editing the markdown sources.
#
man:
	@if command -v ronn >/dev/null 2>&1; then \
	    for f in doc/*.md; do ronn --roff --html --manual="greyd manual" --organization="greyd.org" $$f; done; \
	else echo "ronn not installed; using committed man pages"; fi

#
# Configuration samples, init scripts & systemd units. All are generated
# from the corresponding .in templates with the configured paths.
#
conf: $(CONF_FILES) $(UNIT_FILES)

units: $(UNIT_FILES)

etc/%: etc/%.in
	$(SED) $(CONF_SUBST) <$< >$@

$(UNIT_DIR)/%: $(UNIT_DIR)/%.in
	$(SED) $(CONF_SUBST) <$< >$@

install: build conf
	$(INSTALL) -d -m 0755 $(DESTDIR)$(sbindir)
	for p in $(PROGRAMS); do $(INSTALL) -m 0750 $(BINDIR)/$$p $(DESTDIR)$(sbindir)/$$p; done
	$(INSTALL) -d -m 0755 $(DESTDIR)$(sysconfdir)/$(PACKAGE)
	for f in $(CONF_FILES); do $(INSTALL) -m 0644 $$f $(DESTDIR)$(sysconfdir)/$(PACKAGE)/; done
	$(INSTALL) -d -m 0755 $(DESTDIR)$(unitdir)
	for f in $(UNIT_FILES); do $(INSTALL) -m 0644 $$f $(DESTDIR)$(unitdir)/; done
	$(INSTALL) -d -m 0755 $(DESTDIR)$(mandir)/man8 $(DESTDIR)$(mandir)/man5
	for f in $(MAN8); do $(INSTALL) -m 0644 $$f $(DESTDIR)$(mandir)/man8/; done
	for f in $(MAN5); do $(INSTALL) -m 0644 $$f $(DESTDIR)$(mandir)/man5/; done
	$(INSTALL) -d -m 0755 $(DESTDIR)$(docdir)
	$(INSTALL) -m 0644 README.md COPYING AUTHORS NEWS ChangeLog $(DESTDIR)$(docdir)/
	$(INSTALL) -m 0644 adapters/db/mysql/mysql_schema.sql adapters/db/postgresql/postgresql_schema.sql $(DESTDIR)$(docdir)/

uninstall:
	for p in $(PROGRAMS); do rm -f $(DESTDIR)$(sbindir)/$$p; done
	for f in $(UNIT_FILES); do rm -f $(DESTDIR)$(unitdir)/$$(basename $$f); done
	for f in $(MAN8); do rm -f $(DESTDIR)$(mandir)/man8/$$(basename $$f); done
	for f in $(MAN5); do rm -f $(DESTDIR)$(mandir)/man5/$$(basename $$f); done
	rm -rf $(DESTDIR)$(docdir)

dist:
	@mkdir -p dist
	git archive --format=tar.gz --prefix=$(PACKAGE)-$(VERSION)/ -o dist/$(PACKAGE)-$(VERSION).tar.gz HEAD

docker:
	docker build -f packages/docker/Dockerfile -t mikeyaustin/$(PACKAGE):go .

clean:
	rm -rf $(BINDIR) dist $(CONF_FILES) $(UNIT_FILES)

distclean: clean
	rm -rf .tools

# Packaging, release and coverage helpers.
include packages/release.mk
include packages/integration/integration.mk
