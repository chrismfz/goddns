# -------------------------------
# Project directories & binary
# (cloned from the cfm Makefile workflow)
# -------------------------------
VERSION      ?= $(shell date +%Y.%m.%d)
BUILD_TIME   ?= $(shell date -u +"%Y-%m-%dT%H:%M:%S")
TAG          ?= v$(VERSION)

RPM_VERSION  := $(shell echo "$(VERSION)" | sed 's/-.*//; s/[^A-Za-z0-9._+~]/./g')
RPM_TS       := $(shell echo "$(BUILD_TIME)" | sed 's/.*T//; s/://g')
RPM_RELEASE  := 1.$(RPM_TS)
RPM_ARCH     := $(shell rpm --eval '%{_arch}' 2>/dev/null || echo x86_64)


BIN_DIR := bin
MAIN_DIR := cmd/goddns
BINARY := $(BIN_DIR)/goddns
PKGROOT      ?= build/pkgroot
RPMTOP       ?= packaging/rpm
SPECFILE     ?= $(RPMTOP)/SPECS/goddns.spec
ARCH         ?= x86_64


override ARCH    := amd64
override VERSION := $(shell date +%Y.%m.%d-%H%M%S)
override PKGROOT := build/pkgroot
override OUTDIR  := build/deb
BIN := bin/goddns
CONFIG_DIR := configs
SCRIPTS_DIR := scripts
DEB_SRC := packaging/debian/DEBIAN


# --- Remote Sync ---
REMOTE_USER ?= chris
REMOTE_HOST ?= repo.nixpal.com
REMOTE_PORT ?= 65535
REMOTE_DIR  ?= ~/packages/
SYNC_ON_RELEASE ?= 1

# rsync options (ασφαλής default)
RSYNC_FLAGS ?= -av --partial --inplace
SSH_CMD     ?= ssh -p $(REMOTE_PORT)


# -------------------------------
# Go build target config (CPU/OS)
# -------------------------------
GOOS    ?= linux
GOARCH  ?= amd64
GOAMD64 ?= v1
GOAMD64 := $(strip $(GOAMD64))
CGO_ENABLED ?= 0
# v1=vintage (μέγιστη συμβατότητα), v2, v3, v4

# -------------------------------
# Phony targets
# -------------------------------
.PHONY: help setup update build run clean git clean-deb clean-rpm distclean vet test

# -------------------------------
# Help
# -------------------------------
help: ## Show this help message
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

# -------------------------------
# Setup
# -------------------------------
setup: ## First-time setup after git clone
	go mod tidy
	@echo "✅ Setup complete."

update: ## Update all dependencies
	@echo "🔍 Checking for module updates..."
	go list -m -u all | grep -E '\[|\.'
	go get -u ./...
	go mod tidy
	@echo "✅ Dependencies updated."

vet: ## Run go vet on all packages
	go vet ./...

test: ## Run unit tests
	go test ./...

# -------------------------------
# Build
# -------------------------------
build: vet ## Build the binary into ./bin/
	@mkdir -p $(BIN_DIR)
	@echo "→ Building for $(GOOS)/$(GOARCH) (GOAMD64=$(GOAMD64), CGO_ENABLED=$(CGO_ENABLED))"
	env -u GOAMD64 \
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOAMD64=$(GOAMD64) CGO_ENABLED=$(CGO_ENABLED) \
	go build -a \
		-tags netgo,osusergo \
		-ldflags "-X 'main.Version=$(shell date +%Y.%m.%d)' -X 'main.BuildTime=$(shell date +%Y-%m-%dT%H:%M:%S)'" \
		-o $(BINARY) ./$(MAIN_DIR)
	@echo "✅ Built: $(BINARY)"

run: build ## Run the application
	@./$(BINARY)

# -------------------------------
# Clean
# -------------------------------
# Καθαρίζει το binary και τα staged package payload directories
clean:
	@test -n "$(PKGROOT)" && test "$(PKGROOT)" != "/"
	@rm -f "$(BINARY)"
	@rm -rf "$(PKGROOT)/DEBIAN"
	@rm -rf "$(PKGROOT)/etc"
	@rm -rf "$(PKGROOT)/usr"
	@rm -rf "$(PKGROOT)/lib"
	@rm -rf "$(PKGROOT)/var"
	@rm -f  "$(PKGROOT)/LICENSE"
	@echo "🧹 Cleaned: $(BINARY), staged package payload under $(PKGROOT)"

# Καθαρίζει DEB artifacts (deb πακέτα + staging)
clean-deb:
	@rm -rf build/deb
	@rm -f  build/*.deb build/deb/*.deb build/deb/*/*.deb
	@# προαιρετικά: καθάρισε και ό,τι deb έμεινε κάπου αλλού
	@find build -maxdepth 2 -type f -name '*.deb' -delete 2>/dev/null || true
	@echo "🧹 Cleaned: deb artifacts"

# Καθαρίζει RPM artifacts αλλά ΔΕΝ αγγίζει SPECS/
clean-rpm:
	@rm -rf packaging/rpm/BUILD packaging/rpm/BUILDROOT
	@rm -rf packaging/rpm/RPMS packaging/rpm/SRPMS packaging/rpm/SOURCES
	@find packaging/rpm -type f -name '*.rpm' -delete 2>/dev/null || true
	@echo "🧹 Cleaned: rpm artifacts (kept SPECS/)"

# Πλήρες cleanup (ό,τι κάνει το clean + deb + rpm)
distclean: clean clean-deb clean-rpm
	@echo "🧨 Distclean done"



# -------------------------------
# Git helper
# -------------------------------
git: ## Commit + push με προσαρμοσμένο μήνυμα
	@read -p "Enter commit message: " MSG && \
	git add . && \
	git commit -m "$$MSG" && \
	git push


deb: build ## Δημιουργεί .deb
	@echo "PKGROOT=[$(PKGROOT)] OUTDIR=[$(OUTDIR)]"
	@test -n "$(PKGROOT)" && test -n "$(OUTDIR)"
	@rm -rf "$(PKGROOT)" && mkdir -p "$(PKGROOT)/DEBIAN" \
		"$(PKGROOT)/usr/bin" \
		"$(PKGROOT)/lib/systemd/system" \
		"$(PKGROOT)/usr/share/goddns/configs" \
		"$(PKGROOT)/usr/share/goddns/scripts" \
		"$(PKGROOT)/etc/goddns" \
		"$(OUTDIR)"
	@chmod 0700 "$(PKGROOT)/etc/goddns"

	# copy DEBIAN metadata/scripts
	@cp -a "$(DEB_SRC)/." "$(PKGROOT)/DEBIAN/"
	@sed -i "s/^Version:.*/Version: $(VERSION)-1/" "$(PKGROOT)/DEBIAN/control"

	# payload
	@install -m0755 "$(BIN)" "$(PKGROOT)/usr/bin/goddns"
	@install -m0640 "$(CONFIG_DIR)/goddns.service" "$(PKGROOT)/lib/systemd/system/goddns.service"
	@install -m0640 "$(CONFIG_DIR)/goddns.conf"    "$(PKGROOT)/etc/goddns/goddns.conf"

	@rsync -a --delete "$(CONFIG_DIR)/" "$(PKGROOT)/usr/share/goddns/configs/"
	@rsync -a --delete "$(SCRIPTS_DIR)/" "$(PKGROOT)/usr/share/goddns/scripts/"
	# executables
	@chmod 0755 "$(PKGROOT)/DEBIAN/postinst" "$(PKGROOT)/DEBIAN/prerm" "$(PKGROOT)/DEBIAN/postrm" 2>/dev/null || true

	# build artifact -> build/deb/
	@fakeroot dpkg-deb --build "$(PKGROOT)" "$(OUTDIR)/goddns_$(VERSION)-1_$(ARCH).deb"
	@echo "📦 Built: $(OUTDIR)/goddns_$(VERSION)-1_$(ARCH).deb"


stage-pkgroot: build
	@echo "→ Staging into $(PKGROOT)"
	# binary
	@mkdir -p $(PKGROOT)/usr/bin
	@cp -f $(BINARY) $(PKGROOT)/usr/bin/goddns
	# configs
	@mkdir -p $(PKGROOT)/etc/goddns
	@chmod 0700 $(PKGROOT)/etc/goddns
	@[ -f $(PKGROOT)/etc/goddns/goddns.conf ] || install -m0640 $(CONFIG_DIR)/goddns.conf $(PKGROOT)/etc/goddns/goddns.conf

	# === ship ALL example configs ===
	@mkdir -p $(PKGROOT)/usr/share/goddns/configs
	@rsync -a --delete "$(CONFIG_DIR)/" "$(PKGROOT)/usr/share/goddns/configs/"
	@mkdir -p $(PKGROOT)/usr/share/goddns/scripts
	@rsync -a --delete "$(SCRIPTS_DIR)/" "$(PKGROOT)/usr/share/goddns/scripts/"

	# systemd unit (RPM-friendly path)
	@mkdir -p $(PKGROOT)/usr/lib/systemd/system
	@cp -f $(CONFIG_DIR)/goddns.service $(PKGROOT)/usr/lib/systemd/system/goddns.service


rpm_prep_dirs:
	@mkdir -p $(RPMTOP)/{BUILD,BUILDROOT,RPMS,SRPMS,SPECS,SOURCES}

rpm_spec_version:
	@sed -i 's/^Version:.*/Version:        $(RPM_VERSION)/' $(SPECFILE)
	@sed -i 's/^Release:.*/Release:        $(RPM_RELEASE)%{?dist}/' $(SPECFILE)


.PHONY: stage-rpm
stage-rpm: stage-pkgroot
	@echo "→ Staging RPM systemd unit"
	@mkdir -p $(PKGROOT)/usr/lib/systemd/system
	@cp -f $(CONFIG_DIR)/goddns.service $(PKGROOT)/usr/lib/systemd/system/goddns.service


# --- RPM (.rpm) ---
rpm: rpm_prep_dirs rpm_spec_version stage-rpm ## Δημιουργεί .rpm
	@echo "→ Creating RPM package: goddns-$(RPM_VERSION)-$(RPM_RELEASE)"
	@rpmbuild \
	  --define "_topdir $(CURDIR)/$(RPMTOP)" \
	  --define "_binary_payload w9.gzdio" \
	  --define "debug_package %{nil}" \
	  --define "pkgroot $(CURDIR)/$(PKGROOT)" \
	  --define "projectroot $(CURDIR)" \
	  --buildroot "$(CURDIR)/$(RPMTOP)/BUILDROOT" \
	  --target $(RPM_ARCH) \
	  -bb $(SPECFILE)
	@echo "✅ RPMs under: $(RPMTOP)/RPMS/$(RPM_ARCH)"


# --- Sync both DEB & RPM to remote repo ---
.PHONY: sync
sync: ## Sync τελευταία .deb + .rpm στο remote repo
	@set -euo pipefail; \
	DEB_FILE="$$(ls -1t build/deb/goddns_*_amd64.deb | head -n1)"; \
	RPM_FILE="$$(ls -1t packaging/rpm/RPMS/*/goddns-*.rpm | head -n1)"; \
	[ -n "$$DEB_FILE" ] || { echo "❌ No .deb package found in build/deb"; exit 1; }; \
	[ -n "$$RPM_FILE" ] || { echo "❌ No .rpm package found in packaging/rpm/RPMS"; exit 1; }; \
	echo "🌐 Syncing to $(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_DIR)"; \
	$(SSH_CMD) $(REMOTE_USER)@$(REMOTE_HOST) "mkdir -p $(REMOTE_DIR)/deb $(REMOTE_DIR)/rpm"; \
	echo "→ Upload: $$DEB_FILE -> $(REMOTE_DIR)/deb/"; \
	rsync $(RSYNC_FLAGS) -e "$(SSH_CMD)" "$$DEB_FILE" "$(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_DIR)/deb/"; \
	echo "→ Upload: $$RPM_FILE -> $(REMOTE_DIR)/rpm/"; \
	rsync $(RSYNC_FLAGS) -e "$(SSH_CMD)" "$$RPM_FILE" "$(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_DIR)/rpm/"; \
	echo "→ Upload: checksums.txt -> $(REMOTE_DIR)/"; \
	if [ -f checksums.txt ]; then \
	  rsync $(RSYNC_FLAGS) -e "$(SSH_CMD)" checksums.txt "$(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_DIR)/"; \
	fi; \
	echo "✅ Remote sync complete."


.PHONY: release

GH := gh

release: test deb rpm ## Πλήρες release: deb+rpm+GitHub release with assets
	@set -euo pipefail; \
	echo "🔐 Checking GitHub auth..."; \
	$(GH) auth status -h github.com >/dev/null || { echo "Run: gh auth login"; exit 1; }; \
	DEB_FILE="$$(ls -1t build/deb/goddns_*_amd64.deb | head -n1)"; \
	RPM_FILE="$$(ls -1t packaging/rpm/RPMS/*/goddns-*.rpm | head -n1)"; \
	[ -n "$$DEB_FILE" ] || { echo "No .deb package found in build/deb"; exit 1; }; \
	[ -n "$$RPM_FILE" ] || { echo "No .rpm package found in packaging/rpm/RPMS"; exit 1; }; \
	echo "📦 DEB=$$DEB_FILE"; echo "📦 RPM=$$RPM_FILE"; \
	sha256sum "$$DEB_FILE" "$$RPM_FILE" > checksums.txt; \
	REPO="chrismfz/goddns"; \
	# 1) create (no assets). If it exists (422), continue.
	echo "🚀 Ensuring release $(TAG) exists..."; \
	if ! $(GH) release view "$(TAG)" --repo "$$REPO" >/dev/null 2>&1; then \
	  $(GH) release create "$(TAG)" \
	    --repo "$$REPO" \
	    --title "goddns $(TAG)" \
	    --notes "Automated release" \
	    --draft ; \
	  echo "✅ Created draft release $(TAG)."; \
	else \
	  echo "↻ Release $(TAG) already exists."; \
	fi; \
	# 2) upload assets (clobber)
	echo "⬆️  Uploading: $$DEB_FILE $$RPM_FILE"; \
	$(GH) release upload "$(TAG)" "$$DEB_FILE" "$$RPM_FILE" checksums.txt \
	  --repo "$$REPO" --clobber; \
	echo "✅ Assets uploaded."; \
	# 3) publish (optional – only if you want non-draft)
	echo "📣 Publishing release..."; \
	$(GH) release edit "$(TAG)" --repo "$$REPO" --draft=false ; \
	echo "✅ Release $(TAG) published."
