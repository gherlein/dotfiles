# Makefile for the gherlein Claude Code plugin.
#
# This is a skills plugin -- there is no compiled artifact. "build" and "test"
# therefore mean "validate the shippable skills", and the headline target is
# `release`, which tags the current version and pushes it so users receive it.
#
# This repo is self-hosting: its own .claude-plugin/marketplace.json lists the
# plugin with a local "./" source, so there is no separate marketplace repo to
# update -- tagging and pushing this repo IS the release.

SHELL       := bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:
.DEFAULT_GOAL := help

# --- configuration -----------------------------------------------------------

MAIN_BRANCH := main
PLUGIN_JSON := .claude-plugin/plugin.json
MKT_JSON    := .claude-plugin/marketplace.json

# Version is read straight from plugin.json -- the single source of truth. A
# release is authored by bumping plugin.json + CHANGELOG.md; `release` never
# invents a version, it only publishes the one that is already committed.
VERSION := $(shell jq -r .version $(PLUGIN_JSON) 2>/dev/null)
TAG     := v$(VERSION)

# Name of this plugin as it appears in marketplace.json (.plugins[].name).
PLUGIN_NAME := gherlein

.PHONY: help build test run-tests check clean release

# --- help --------------------------------------------------------------------

help: ## Show this help
	@printf 'gherlein plugin -- version %s\n\n' "$(VERSION)"
	@printf 'Targets:\n'
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

# --- validation (build/test surface) -----------------------------------------

check: ## Validate skills reference only declared namespaces (gherlein:, superpowers:, claude-security:)
	@scripts/check-self-contained.sh

build: check ## Validate the plugin is shippable (alias for check)

test: check ## Run validation checks

run-tests: check ## Run validation checks (alias for test)

clean: ## Remove build scratch (bin/)
	@rm -rf bin

# --- release -----------------------------------------------------------------

release: check ## Tag plugin.json's version and push it (self-hosting marketplace)
	@printf '==> Preparing release %s\n' "$(TAG)"

	# ----- preflight: version -----
	if [ -z "$(VERSION)" ] || [ "$(VERSION)" = "null" ]; then
	  echo "ERROR: could not read version from $(PLUGIN_JSON) (is jq installed?)" >&2; exit 1
	fi
	if ! printf '%s' "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$'; then
	  echo "ERROR: version '$(VERSION)' is not semver (X.Y.Z)" >&2; exit 1
	fi

	# ----- preflight: repo state -----
	branch="$$(git rev-parse --abbrev-ref HEAD)"
	if [ "$$branch" != "$(MAIN_BRANCH)" ]; then
	  echo "ERROR: on branch '$$branch', expected '$(MAIN_BRANCH)'" >&2; exit 1
	fi
	if [ -n "$$(git status --porcelain)" ]; then
	  echo "ERROR: working tree is not clean -- commit or stash first" >&2; exit 1
	fi
	if ! head -n 20 CHANGELOG.md | grep -qx "## $(TAG)"; then
	  echo "ERROR: CHANGELOG.md has no '## $(TAG)' entry near the top" >&2; exit 1
	fi

	# ----- preflight: tag must not collide with a different commit -----
	head_sha="$$(git rev-parse HEAD)"
	if git rev-parse -q --verify "refs/tags/$(TAG)" >/dev/null; then
	  if [ "$$(git rev-list -n1 $(TAG))" != "$$head_sha" ]; then
	    echo "ERROR: tag $(TAG) already exists but does not point at HEAD" >&2; exit 1
	  fi
	  echo "note: tag $(TAG) already exists at HEAD -- reusing"
	fi

	# ----- tag + push -----
	if ! git rev-parse -q --verify "refs/tags/$(TAG)" >/dev/null; then
	  echo "==> git tag -a $(TAG)"
	  git tag -a "$(TAG)" -m "Release $(TAG)"
	fi
	echo "==> git push origin $(MAIN_BRANCH) $(TAG)"
	git push origin "$(MAIN_BRANCH)"
	git push origin "$(TAG)"

	# ----- done: hand off the client-side steps make cannot run -----
	mkt_name="$$(jq -r .name "$(MKT_JSON)")"
	printf '\n'
	printf '=== %s published ===\n' "$(TAG)"
	printf 'Tag is live and the marketplace listing tracks this repo. Finish in the client:\n\n'
	printf '  /plugin marketplace update %s\n' "$$mkt_name"
	printf '  /plugin update %s@%s\n' "$(PLUGIN_NAME)" "$$mkt_name"
	printf '  (restart the session so the plugin reloads)\n\n'
	printf 'Then verify the new content landed, e.g.:\n'
	printf '  grep -rc gofinet ~/.claude/plugins/cache/%s/%s/%s/skills/\n' "$$mkt_name" "$(PLUGIN_NAME)" "$(VERSION)"
