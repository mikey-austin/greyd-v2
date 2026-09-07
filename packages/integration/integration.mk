#
# Integration harnesses (packages/integration). Included from the Makefile,
# which provides GO, BINDIR, PROGRAMS, PACKAGE and VERSION.
#
#   make test-integration        build the harness image and run it privileged
#   make test-integration-host   run the Linux harness directly on this host
#                                (root; installs iptables rules, use a VM)
#   make vet-openbsd             cross-vet the OpenBSD code paths run-openbsd.sh relies on
#

INTEGRATION_DIR   := packages/integration
INTEGRATION_IMAGE ?= $(PACKAGE)-integration:$(VERSION)
DOCKER            ?= docker
SUDO              ?= sudo
# Extra flags for docker run, e.g. -e GREYD_IT_WAIT=40 or -e GREYD_IT_KEEP=1.
INTEGRATION_RUN_FLAGS ?=

SOAK_MINUTES ?= 30

.PHONY: test-integration test-integration-image test-integration-host test-soak vet-openbsd

test-integration-image:
	$(DOCKER) build -f $(INTEGRATION_DIR)/Dockerfile -t $(INTEGRATION_IMAGE) .

# The container needs NET_ADMIN/NET_RAW (ipset, NFLOG, conntrack, iptables),
# SYS_CHROOT and SETUID/SETGID (privilege separation); --privileged is the
# simplest way to grant them all.
test-integration: test-integration-image
	$(DOCKER) run --rm --privileged $(INTEGRATION_RUN_FLAGS) $(INTEGRATION_IMAGE)

# Soak run in the same privileged image (packages/integration/soak.sh);
# the samples CSV is copied out of the container into ./soak.csv.
test-soak: test-integration-image
	$(DOCKER) run --rm --privileged --name $(PACKAGE)-soak $(INTEGRATION_RUN_FLAGS) \
	    -e SOAK_MINUTES=$(SOAK_MINUTES) -v "$(CURDIR)":/out \
	    $(INTEGRATION_IMAGE) sh -c 'packages/integration/soak.sh; rc=$$?; cp /var/log/greyd/soak.csv /out/soak.csv 2>/dev/null; exit $$rc'

test-integration-host: $(PROGRAMS)
	$(SUDO) env GREYD_BIN=$(abspath $(BINDIR)) $(INTEGRATION_DIR)/run-linux.sh

vet-openbsd:
	GOOS=openbsd GOARCH=amd64 $(GO) vet -unreachable=false ./...
