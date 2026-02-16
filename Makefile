MODULE       := github.com/ponder2000/guardian
VERSION      ?= 0.2.0
COMMIT       := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME   := $(shell date '+%Y-%m-%d %H:%M:%S %Z')
AUTHOR       := Jay Saha
LDFLAGS      := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X 'main.buildTime=$(BUILD_TIME)' -X 'main.author=$(AUTHOR)'

BINARIES     := guardiand guardian-cli license-gen

# Default to current OS/arch
GOOS         ?= $(shell go env GOOS)
GOARCH       ?= $(shell go env GOARCH)

# Output directory based on target OS
OUTDIR       := bin/$(GOOS)

# Debian package layout
DEB_ROOT     := bin/deb-staging
DEB_PKG      := bin/guardian_$(VERSION)_amd64.deb

.PHONY: all build build-linux build-macos test clean package-deb

all: build

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

build: $(addprefix $(OUTDIR)/,$(BINARIES))

$(OUTDIR)/%: cmd/%/main.go $(shell find internal/ -name '*.go') go.mod go.sum
	@mkdir -p $(OUTDIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o $@ ./cmd/$*/

build-linux:
	$(MAKE) build GOOS=linux GOARCH=amd64

build-macos:
	$(MAKE) build GOOS=darwin GOARCH=arm64

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

test:
	go test ./... -v

test-race:
	go test -race ./...

# ---------------------------------------------------------------------------
# Debian package
# ---------------------------------------------------------------------------

package-deb: build-linux
	rm -rf $(DEB_ROOT)
	# Binaries
	mkdir -p $(DEB_ROOT)/usr/local/bin
	cp bin/linux/guardiand   $(DEB_ROOT)/usr/local/bin/
	cp bin/linux/guardian-cli $(DEB_ROOT)/usr/local/bin/
	cp bin/linux/license-gen  $(DEB_ROOT)/usr/local/bin/
	# Configuration
	mkdir -p $(DEB_ROOT)/etc/guardian
	cp configs/guardian.conf.example $(DEB_ROOT)/etc/guardian/guardian.conf
	# Systemd unit
	mkdir -p $(DEB_ROOT)/lib/systemd/system
	cp configs/guardian.service $(DEB_ROOT)/lib/systemd/system/
	# Runtime directories
	mkdir -p $(DEB_ROOT)/var/run/guardian
	mkdir -p $(DEB_ROOT)/var/log/guardian
	# DEBIAN control
	mkdir -p $(DEB_ROOT)/DEBIAN
	@printf 'Package: guardian\n\
Version: $(VERSION)\n\
Section: admin\n\
Priority: optional\n\
Architecture: amd64\n\
Maintainer: Guardian Authors\n\
Description: Guardian License Enforcement Daemon\n\
 Hardware-bound license enforcement service that provides\n\
 cryptographic license validation over Unix domain sockets.\n' > $(DEB_ROOT)/DEBIAN/control
	# postinst — enable and start the service
	@printf '#!/bin/sh\nset -e\nsystemctl daemon-reload\nsystemctl enable guardian.service\necho "Guardian installed. Run: systemctl start guardian"\n' > $(DEB_ROOT)/DEBIAN/postinst
	chmod 755 $(DEB_ROOT)/DEBIAN/postinst
	# prerm — stop the service before removal
	@printf '#!/bin/sh\nset -e\nsystemctl stop guardian.service 2>/dev/null || true\nsystemctl disable guardian.service 2>/dev/null || true\n' > $(DEB_ROOT)/DEBIAN/prerm
	chmod 755 $(DEB_ROOT)/DEBIAN/prerm
	# conffiles — mark config so upgrades don't overwrite edits
	@echo "/etc/guardian/guardian.conf" > $(DEB_ROOT)/DEBIAN/conffiles
	# Build .deb
	dpkg-deb --build --root-owner-group $(DEB_ROOT) $(DEB_PKG)
	@echo ""
	@echo "Package created: $(DEB_PKG)"

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

clean:
	rm -rf bin/linux bin/macos bin/darwin bin/deb-staging bin/*.deb
