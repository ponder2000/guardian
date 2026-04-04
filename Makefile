MODULE       := github.com/ponder2000/guardian
VERSION      ?= 0.3.0
COMMIT       := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME   := $(shell date '+%Y-%m-%d %H:%M:%S %Z')
AUTHOR       := Jay Saha
LDFLAGS      := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X 'main.buildTime=$(BUILD_TIME)' -X 'main.author=$(AUTHOR)'

BINARIES     := guardiand guardian-cli license-gen guardian-manager

# Default to current OS/arch
GOOS         ?= $(shell go env GOOS)
GOARCH       ?= $(shell go env GOARCH)

# Output directory based on target OS
OUTDIR       := bin/$(GOOS)

# Debian package layout — DEB_ARCH follows GOARCH (amd64, arm64, etc.)
DEB_ARCH     ?= $(GOARCH)
DEB_ROOT     := bin/deb-staging
DEB_PKG      := bin/guardian_$(VERSION)_$(DEB_ARCH).deb

.PHONY: all build build-linux build-macos test clean package-deb run-manager docker-build docker-push

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

package-deb:
	$(MAKE) build GOOS=linux GOARCH=$(DEB_ARCH)
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
	@echo 'Package: guardian'                                        >  $(DEB_ROOT)/DEBIAN/control
	@echo 'Version: $(VERSION)'                                      >> $(DEB_ROOT)/DEBIAN/control
	@echo 'Section: admin'                                           >> $(DEB_ROOT)/DEBIAN/control
	@echo 'Priority: optional'                                       >> $(DEB_ROOT)/DEBIAN/control
	@echo 'Architecture: $(DEB_ARCH)'                                 >> $(DEB_ROOT)/DEBIAN/control
	@echo 'Maintainer: Guardian Authors'                              >> $(DEB_ROOT)/DEBIAN/control
	@echo 'Description: Guardian License Enforcement Daemon'          >> $(DEB_ROOT)/DEBIAN/control
	@echo ' Hardware-bound license enforcement service that provides' >> $(DEB_ROOT)/DEBIAN/control
	@echo ' cryptographic license validation over Unix domain sockets.' >> $(DEB_ROOT)/DEBIAN/control
	# preinst — stop running daemon before upgrade, clean stale state
	@echo '#!/bin/sh'                                                          >  $(DEB_ROOT)/DEBIAN/preinst
	@echo 'set -e'                                                             >> $(DEB_ROOT)/DEBIAN/preinst
	@echo 'if [ "$$1" = "upgrade" ] || [ "$$1" = "install" ]; then'            >> $(DEB_ROOT)/DEBIAN/preinst
	@echo '    if systemctl is-active --quiet guardian.service 2>/dev/null; then' >> $(DEB_ROOT)/DEBIAN/preinst
	@echo '        echo "Stopping running Guardian daemon ..."'                >> $(DEB_ROOT)/DEBIAN/preinst
	@echo '        systemctl stop guardian.service'                             >> $(DEB_ROOT)/DEBIAN/preinst
	@echo '    fi'                                                             >> $(DEB_ROOT)/DEBIAN/preinst
	@echo '    rm -f /var/run/guardian/guardian.sock'                           >> $(DEB_ROOT)/DEBIAN/preinst
	@echo '    rm -f /var/run/guardian/guardian.pid'                            >> $(DEB_ROOT)/DEBIAN/preinst
	@echo 'fi'                                                                 >> $(DEB_ROOT)/DEBIAN/preinst
	chmod 755 $(DEB_ROOT)/DEBIAN/preinst
	# postinst — reload units, enable, and restart on upgrade
	@echo '#!/bin/sh'                                                          >  $(DEB_ROOT)/DEBIAN/postinst
	@echo 'set -e'                                                             >> $(DEB_ROOT)/DEBIAN/postinst
	@echo 'systemctl daemon-reload'                                            >> $(DEB_ROOT)/DEBIAN/postinst
	@echo 'systemctl enable guardian.service'                                  >> $(DEB_ROOT)/DEBIAN/postinst
	@echo 'mkdir -p /var/run/guardian /var/log/guardian'                        >> $(DEB_ROOT)/DEBIAN/postinst
	@echo 'if [ "$$1" = "upgrade" ]; then'                                     >> $(DEB_ROOT)/DEBIAN/postinst
	@echo '    echo "Restarting Guardian daemon after upgrade ..."'             >> $(DEB_ROOT)/DEBIAN/postinst
	@echo '    systemctl start guardian.service'                                >> $(DEB_ROOT)/DEBIAN/postinst
	@echo 'else'                                                               >> $(DEB_ROOT)/DEBIAN/postinst
	@echo '    echo "Guardian installed. Deploy license and keys, then run:"'  >> $(DEB_ROOT)/DEBIAN/postinst
	@echo '    echo "  sudo systemctl start guardian"'                         >> $(DEB_ROOT)/DEBIAN/postinst
	@echo 'fi'                                                                 >> $(DEB_ROOT)/DEBIAN/postinst
	chmod 755 $(DEB_ROOT)/DEBIAN/postinst
	# prerm — stop the service before removal
	@echo '#!/bin/sh'                                                          >  $(DEB_ROOT)/DEBIAN/prerm
	@echo 'set -e'                                                             >> $(DEB_ROOT)/DEBIAN/prerm
	@echo 'if [ "$$1" = "remove" ] || [ "$$1" = "purge" ]; then'              >> $(DEB_ROOT)/DEBIAN/prerm
	@echo '    systemctl stop guardian.service 2>/dev/null || true'             >> $(DEB_ROOT)/DEBIAN/prerm
	@echo '    systemctl disable guardian.service 2>/dev/null || true'          >> $(DEB_ROOT)/DEBIAN/prerm
	@echo 'fi'                                                                 >> $(DEB_ROOT)/DEBIAN/prerm
	chmod 755 $(DEB_ROOT)/DEBIAN/prerm
	# postrm — clean up runtime state on purge
	@echo '#!/bin/sh'                                                          >  $(DEB_ROOT)/DEBIAN/postrm
	@echo 'set -e'                                                             >> $(DEB_ROOT)/DEBIAN/postrm
	@echo 'if [ "$$1" = "purge" ]; then'                                       >> $(DEB_ROOT)/DEBIAN/postrm
	@echo '    rm -f /var/run/guardian/guardian.sock'                           >> $(DEB_ROOT)/DEBIAN/postrm
	@echo '    rm -f /var/run/guardian/guardian.pid'                            >> $(DEB_ROOT)/DEBIAN/postrm
	@echo '    rmdir /var/run/guardian 2>/dev/null || true'                     >> $(DEB_ROOT)/DEBIAN/postrm
	@echo '    echo "Guardian purged. Remove /etc/guardian/ manually if needed."' >> $(DEB_ROOT)/DEBIAN/postrm
	@echo 'fi'                                                                 >> $(DEB_ROOT)/DEBIAN/postrm
	@echo 'systemctl daemon-reload 2>/dev/null || true'                        >> $(DEB_ROOT)/DEBIAN/postrm
	chmod 755 $(DEB_ROOT)/DEBIAN/postrm
	# conffiles — mark config so upgrades don't overwrite edits
	@echo "/etc/guardian/guardian.conf" > $(DEB_ROOT)/DEBIAN/conffiles
	# Build .deb
	dpkg-deb --build --root-owner-group $(DEB_ROOT) $(DEB_PKG)
	@echo ""
	@echo "Package created: $(DEB_PKG)"

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

run-manager:
	@mkdir -p data
	go run -ldflags "$(LDFLAGS)" ./cmd/guardian-manager/

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------

DOCKER_IMAGE := jaysaha/guardian-manager
DOCKER_TAG   ?= $(VERSION)
DOCKER_PLATFORM ?= linux/amd64

docker-build:
	docker build --platform $(DOCKER_PLATFORM) -t $(DOCKER_IMAGE):$(DOCKER_TAG) -t $(DOCKER_IMAGE):latest .

docker-push: docker-build
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_IMAGE):latest

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

clean:
	rm -rf bin/linux bin/macos bin/darwin bin/deb-staging bin/*.deb
