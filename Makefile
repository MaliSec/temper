# Local developer targets. The pipeline itself lives in scripts/ (build.sh,
# check-policy.sh, verify-build.sh, cut-registry.sh).

SHELL := /bin/bash
INSTALL_DIR ?= $${HOME}/.local/bin

.PHONY: help install-tools toolbox toolbox-run keygen lock build-all policy \
	scan verify test clean lint validate

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install-tools: ## Install apko, melange, cosign, crane, grype, syft, trivy (scripts/install-tools.sh; checksum-pinned)
	./scripts/install-tools.sh

toolbox: ## Build the containerized toolchain (Dockerfile.toolbox)
	docker build -f Dockerfile.toolbox -t temper-toolbox:local .

toolbox-run: ## Run a tool inside the toolbox: make toolbox-run CMD="apko version"
	@mkdir -p .toolbox-cache
	@./scripts/toolbox.sh $(CMD)

keygen: ## Generate the melange signing keypair (never commit the private half)
	./scripts/keygen.sh

lock: ## Regenerate apko lockfiles (all images, or IMAGE=node for one)
	./scripts/build.sh --lock $(if $(IMAGE),--image $(IMAGE))

build-all: ## Build all packages + images locally (scripts/build.sh)
	./scripts/build.sh

policy: ## Run the hardening policy check on dist/ tars (fail-closed)
	./scripts/check-policy.sh

scan: ## Scan locally built images as the release does: policy, then Trivy + Grype per platform (gate: no criticals or known-exploited)
	./scripts/cut-registry.sh scan

verify: ## Verify a published image: make verify REF=registry/org/name@sha256:...
	./scripts/verify-build.sh "$(REF)"

test: ## Run the local test suite (tests/)
	./tests/run.sh

lint: ## Lint all YAML with yamllint (repo config: .yamllint)
	yamllint .

validate: ## Parse all YAML structurally
	@set -euo pipefail; fail=0; \
	files=$$(git ls-files '*.yaml' '*.yml' 2>/dev/null || find . -path ./.git -prune -o \( -name '*.yaml' -o -name '*.yml' \) -print); \
	for f in $$files; do \
	  python3 -c 'import sys, yaml; yaml.safe_load(open(sys.argv[1]))' "$$f" \
	    || { echo "INVALID YAML: $$f"; fail=1; }; \
	done; \
	[ "$$fail" = 0 ] && echo "All YAML parses OK" || exit 1

clean: ## Remove local build artifacts (dist/, local-apk/, stray .apk/.tar)
	rm -rf dist/ local-apk/ apk-cache/
	find . -path ./.git -prune -o -name '*.apk' -print -delete
	find . -path ./.git -prune -o -name '*.tar' -print -delete
