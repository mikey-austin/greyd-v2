#
# greyd - greylisting & blacklisting daemon (Go port)
#
# Common targets:
#   make            build all programs into bin/
#   make test       vet + unit tests (race detector enabled)
#   make generate   regenerate the ANTLR configuration parser
#   make install    install programs, configuration and man pages
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
DESTDIR        ?=

DEFAULT_CONFIG    ?= $(sysconfdir)/$(PACKAGE)/greyd.conf
GREYD_PIDFILE     ?= $(localstatedir)/empty/greyd/greyd.pid
GREYLOGD_PIDFILE  ?= $(localstatedir)/empty/greylogd/greylogd.pid

PROGRAMS       := greyd greydb greyd-setup greylogd
BINDIR         := bin

ANTLR_VERSION  := 4.13.1
ANTLR_JAR      := .tools/antlr-$(ANTLR_VERSION)-complete.jar
ANTLR_URL      := https://www.antlr.org/download/antlr-$(ANTLR_VERSION)-complete.jar
GRAMMAR_DIR    := internal/config/grammar
GRAMMAR        := $(GRAMMAR_DIR)/GreydConf.g4

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
                  -e 's,[@]DEFAULT_CONFIG[@],$(DEFAULT_CONFIG),g' \
                  -e 's,[@]CURL[@],$(CURL),g' \
                  -e 's,[@]libdir[@],$(libdir),g' \
                  -e 's,[@]sbindir[@],$(sbindir),g' \
                  -e 's,[@]localstatedir[@],$(localstatedir),g' \
                  -e 's,[@]sysconfdir[@],$(sysconfdir),g'

CONF_FILES     := etc/greyd.conf etc/greyd.docker.conf etc/greyd.redhat-init \
                  etc/greylogd.redhat-init etc/greyd.debian-init etc/greylogd.debian-init

MAN8           := doc/greyd.8 doc/greylogd.8 doc/greydb.8 doc/greyd-setup.8
MAN5           := doc/greyd.conf.5

.PHONY: all build $(PROGRAMS) generate test test-race test-db-docker lint fmt vet man \
        conf install uninstall dist docker clean distclean tools

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

tools: $(ANTLR_JAR)

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

lint: vet
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./...; else echo "staticcheck not installed; skipping"; fi

test: vet
	$(GO) test -race ./...

test-race: test

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
# Configuration samples & init scripts.
#
conf: $(CONF_FILES)

etc/%: etc/%.in
	$(SED) $(CONF_SUBST) <$< >$@

install: build conf
	$(INSTALL) -d -m 0755 $(DESTDIR)$(sbindir)
	for p in $(PROGRAMS); do $(INSTALL) -m 0750 $(BINDIR)/$$p $(DESTDIR)$(sbindir)/$$p; done
	$(INSTALL) -d -m 0755 $(DESTDIR)$(sysconfdir)/$(PACKAGE)
	for f in $(CONF_FILES); do $(INSTALL) -m 0644 $$f $(DESTDIR)$(sysconfdir)/$(PACKAGE)/; done
	$(INSTALL) -d -m 0755 $(DESTDIR)$(mandir)/man8 $(DESTDIR)$(mandir)/man5
	for f in $(MAN8); do $(INSTALL) -m 0644 $$f $(DESTDIR)$(mandir)/man8/; done
	for f in $(MAN5); do $(INSTALL) -m 0644 $$f $(DESTDIR)$(mandir)/man5/; done
	$(INSTALL) -d -m 0755 $(DESTDIR)$(docdir)
	$(INSTALL) -m 0644 README.md COPYING AUTHORS NEWS ChangeLog $(DESTDIR)$(docdir)/
	$(INSTALL) -m 0644 adapters/db/mysql/mysql_schema.sql adapters/db/postgresql/postgresql_schema.sql $(DESTDIR)$(docdir)/

uninstall:
	for p in $(PROGRAMS); do rm -f $(DESTDIR)$(sbindir)/$$p; done
	for f in $(MAN8); do rm -f $(DESTDIR)$(mandir)/man8/$$(basename $$f); done
	for f in $(MAN5); do rm -f $(DESTDIR)$(mandir)/man5/$$(basename $$f); done
	rm -rf $(DESTDIR)$(docdir)

dist:
	@mkdir -p dist
	git archive --format=tar.gz --prefix=$(PACKAGE)-$(VERSION)/ -o dist/$(PACKAGE)-$(VERSION).tar.gz HEAD

docker:
	docker build -f packages/docker/Dockerfile -t mikeyaustin/$(PACKAGE):go .

clean:
	rm -rf $(BINDIR) dist $(CONF_FILES)

distclean: clean
	rm -rf .tools
