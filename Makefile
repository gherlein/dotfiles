# Makefile for dotfiles management with GNU Stow

# Package list file
PACKAGES_FILE := .stow-packages

# Read packages from file (one per line, skip empty lines and comments)
PACKAGES := $(shell [ -f $(PACKAGES_FILE) ] && grep -v '^\#' $(PACKAGES_FILE) | grep -v '^$$' || echo "")

.PHONY: help stow unstow restow list refresh

help:
	@echo "Dotfiles management with GNU Stow"
	@echo ""
	@echo "Usage:"
	@echo "  make stow      - Stow all packages"
	@echo "  make unstow    - Unstow all packages"
	@echo "  make restow    - Restow all packages (refresh symlinks)"
	@echo "  make list      - List all packages"
	@echo "  make refresh   - Regenerate package list from directories"
	@echo ""
	@echo "Packages are read from: $(PACKAGES_FILE)"
	@echo ""

stow:
	@if [ -z "$(PACKAGES)" ]; then \
		echo "No packages found. Run 'make refresh' first."; \
		exit 1; \
	fi
	@echo "Stowing all packages..."
	@for pkg in $(PACKAGES); do \
		if [ -d $$pkg ]; then \
			echo "Stowing $$pkg..."; \
			stow -v $$pkg; \
		else \
			echo "Warning: Package $$pkg not found, skipping..."; \
		fi \
	done

unstow:
	@if [ -z "$(PACKAGES)" ]; then \
		echo "No packages found. Run 'make refresh' first."; \
		exit 1; \
	fi
	@echo "Unstowing all packages..."
	@for pkg in $(PACKAGES); do \
		if [ -d $$pkg ]; then \
			echo "Unstowing $$pkg..."; \
			stow -D -v $$pkg; \
		else \
			echo "Warning: Package $$pkg not found, skipping..."; \
		fi \
	done

restow:
	@if [ -z "$(PACKAGES)" ]; then \
		echo "No packages found. Run 'make refresh' first."; \
		exit 1; \
	fi
	@echo "Restowing all packages..."
	@for pkg in $(PACKAGES); do \
		if [ -d $$pkg ]; then \
			echo "Restowing $$pkg..."; \
			stow -R -v $$pkg; \
		else \
			echo "Warning: Package $$pkg not found, skipping..."; \
		fi \
	done

list:
	@if [ -z "$(PACKAGES)" ]; then \
		echo "No packages found. Run 'make refresh' first."; \
		exit 1; \
	fi
	@echo "Available packages:"
	@for pkg in $(PACKAGES); do \
		if [ -d $$pkg ]; then \
			echo "  [ok]      $$pkg"; \
		else \
			echo "  [missing] $$pkg"; \
		fi \
	done

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
