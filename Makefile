# Makefile for dotfiles management with GNU Stow

# Package list file
PACKAGES_FILE := .stow-packages

# Read packages from file (one per line, skip empty lines and comments)
PACKAGES := $(shell [ -f $(PACKAGES_FILE) ] && grep -v '^\#' $(PACKAGES_FILE) | grep -v '^$$' || echo "")

# Host-specific packages are named "<tool>-<shorthostname>" (e.g. hax-helios).
# Every host stows the shared packages plus only the ones matching its own
# short hostname; packages for other hosts are left alone.
HOST := $(shell hostname -s)
HOSTS := io europa helios

HOST_PACKAGES := $(foreach h,$(HOSTS),$(filter %-$(h),$(PACKAGES)))
SHARED_PACKAGES := $(filter-out $(HOST_PACKAGES),$(PACKAGES))
MY_HOST_PACKAGES := $(filter %-$(HOST),$(PACKAGES))
ACTIVE_PACKAGES := $(SHARED_PACKAGES) $(MY_HOST_PACKAGES)
SKIPPED_PACKAGES := $(filter-out $(MY_HOST_PACKAGES),$(HOST_PACKAGES))

.PHONY: help install stow unstow restow adopt list refresh

help:
	@echo "Dotfiles management with GNU Stow"
	@echo ""
	@echo "Usage:"
	@echo "  make install   - Refresh package list then stow (shared + this host)"
	@echo "  make stow      - Stow shared packages + this host's packages"
	@echo "  make unstow    - Unstow shared packages + this host's packages"
	@echo "  make restow    - Restow shared packages + this host's packages"
	@echo "  make adopt     - Adopt existing files then stow (use on new host with existing configs)"
	@echo "  make list      - List active packages for this host (and skipped ones)"
	@echo "  make refresh   - Regenerate package list from directories"
	@echo ""
	@echo "Packages are read from: $(PACKAGES_FILE)"
	@echo "This host: $(HOST)   Host-specific suffixes: $(HOSTS)"
	@echo "Host-specific packages are named '<tool>-<host>' (e.g. hax-helios)."
	@echo ""

# Regenerate the package list, then stow. refresh and stow run as separate
# sub-makes so that stow re-reads the freshly written .stow-packages
# (PACKAGES is expanded once at parse time with :=, before refresh runs).
install:
	@$(MAKE) refresh
	@$(MAKE) stow

stow:
	@if [ -z "$(ACTIVE_PACKAGES)" ]; then \
		echo "No packages found. Run 'make refresh' first."; \
		exit 1; \
	fi
	@echo "Stowing packages for host '$(HOST)' (shared + this host)..."
	@if [ -n "$(strip $(SKIPPED_PACKAGES))" ]; then \
		echo "Skipping other-host packages: $(SKIPPED_PACKAGES)"; \
	fi
	@for pkg in $(ACTIVE_PACKAGES); do \
		if [ -d $$pkg ]; then \
			echo "Stowing $$pkg..."; \
			stow -n $$pkg 2>&1 | grep -E 'existing target' \
				| sed -E -e 's|.*over existing target (.+) since .*|\1|' -e 's|.*existing target[^:]*: ||' \
				| while read -r target; do \
					[ -n "$$target" ] || continue; \
					[ -e "$$HOME/$$target" ] && [ ! -L "$$HOME/$$target" ] || continue; \
					echo "  Removing conflicting file: $$HOME/$$target"; \
					rm -f "$$HOME/$$target"; \
				done; \
			stow -v $$pkg; \
		else \
			echo "Warning: Package $$pkg not found, skipping..."; \
		fi \
	done
	curl -fsSL https://raw.githubusercontent.com/gherlein/localdev/main/install.sh | bash

unstow:
	@if [ -z "$(ACTIVE_PACKAGES)" ]; then \
		echo "No packages found. Run 'make refresh' first."; \
		exit 1; \
	fi
	@echo "Unstowing all packages..."
	@for pkg in $(ACTIVE_PACKAGES); do \
		if [ -d $$pkg ]; then \
			echo "Unstowing $$pkg..."; \
			stow -D -v $$pkg; \
		else \
			echo "Warning: Package $$pkg not found, skipping..."; \
		fi \
	done

restow:
	@if [ -z "$(ACTIVE_PACKAGES)" ]; then \
		echo "No packages found. Run 'make refresh' first."; \
		exit 1; \
	fi
	@echo "Restowing all packages..."
	@for pkg in $(ACTIVE_PACKAGES); do \
		if [ -d $$pkg ]; then \
			echo "Restowing $$pkg..."; \
			stow -R -v $$pkg; \
		else \
			echo "Warning: Package $$pkg not found, skipping..."; \
		fi \
	done

adopt:
	@if [ -z "$(ACTIVE_PACKAGES)" ]; then \
		echo "No packages found. Run 'make refresh' first."; \
		exit 1; \
	fi
	@echo "Adopting existing files and stowing all packages..."
	@echo "Run 'git diff' afterwards to review what was pulled in from this host."
	@for pkg in $(ACTIVE_PACKAGES); do \
		if [ -d $$pkg ]; then \
			echo "Adopting $$pkg..."; \
			stow --adopt -v $$pkg; \
		else \
			echo "Warning: Package $$pkg not found, skipping..."; \
		fi \
	done

list:
	@if [ -z "$(ACTIVE_PACKAGES)" ]; then \
		echo "No packages found. Run 'make refresh' first."; \
		exit 1; \
	fi
	@echo "Host: $(HOST)"
	@echo "Active packages (shared + this host):"
	@for pkg in $(ACTIVE_PACKAGES); do \
		if [ -d $$pkg ]; then \
			echo "  [ok]      $$pkg"; \
		else \
			echo "  [missing] $$pkg"; \
		fi \
	done
	@if [ -n "$(strip $(SKIPPED_PACKAGES))" ]; then \
		echo "Skipped (other hosts):"; \
		for pkg in $(SKIPPED_PACKAGES); do echo "  [skip]    $$pkg"; done; \
	fi

refresh:
	@echo "Scanning for stow packages..."
	@echo "# Auto-generated package list - do not edit manually" > $(PACKAGES_FILE)
	@echo "# Generated: $$(date)" >> $(PACKAGES_FILE)
	@echo "# Run 'make refresh' to regenerate this file" >> $(PACKAGES_FILE)
	@echo "#" >> $(PACKAGES_FILE)
	@for dir in */; do \
		pkg=$${dir%/}; \
		if [ "$$pkg" != "*" ]; then \
			echo "$$pkg" >> $(PACKAGES_FILE); \
		fi \
	done
	@echo ""
	@echo "Package list written to $(PACKAGES_FILE):"
	@cat $(PACKAGES_FILE)
	@echo ""
	@echo "Found $$(grep -v '^\#' $(PACKAGES_FILE) | grep -v '^$$' | wc -l | tr -d ' ') packages"
