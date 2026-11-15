SHELL := /bin/sh
COMPOSE := ./scripts/compose.sh
CASE ?= all
AGENT_GO_IMAGE := golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea
AGENT_GO := docker run --rm --network none -v "$(CURDIR)/agent:/src" -w /src -e GOFLAGS=-mod=readonly -e GOTOOLCHAIN=local -e GOPROXY=off -e CGO_ENABLED=0 $(AGENT_GO_IMAGE)

.PHONY: agent test-agent init build up down logs check test test-unit test-integration test-runtime test-ui test-journey test-demo demo-up demo-step demo-down backup restore reset-password prune

init:
	./scripts/init.sh

build: init
	$(COMPOSE) --profile images build
	$(MAKE) prune

# Each rebuild leaves the previous Numen images untagged; remove only those, never other projects'.
prune:
	docker image prune -f --filter label=org.pruferva.asset-monitor.image=true

up: build
	$(COMPOSE) up -d --wait app worker scheduler runner-broker fetch-gateway ingress-push ingress-agent
	$(COMPOSE) --profile setup run --rm bootstrap-operator

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs --tail=100 -f app worker scheduler runner-broker ingress-push ingress-agent db

check: init
	$(COMPOSE) --profile test run --build --no-deps --rm backend-tests ruff check --no-cache numen tests
	$(COMPOSE) --profile test run --build --no-deps --rm frontend-tests npm run lint
	$(COMPOSE) --profile test run --no-deps --rm frontend-tests npm run typecheck
	$(COMPOSE) --profile test run --no-deps --rm frontend-tests npm run build

test: test-unit test-integration test-runtime test-ui

test-unit: init
	$(COMPOSE) --profile test run --build --no-deps --rm backend-tests pytest -q -p no:cacheprovider tests/test_api.py tests/test_workflows.py tests/test_artifacts.py tests/test_accounts.py tests/test_repositories.py tests/test_intake.py tests/test_dependencies.py tests/test_triage.py tests/test_analysis.py
	$(COMPOSE) --profile test run --build --no-deps --rm runner-tests

test-integration: init
	./scripts/test-backend.sh "$(CASE)"

test-runtime: init
	./scripts/test-runtime.sh "$(CASE)"

test-ui: init
	./scripts/test-ui.sh "$(CASE)"

test-journey: build
	./scripts/test-journey.sh

# The demo smoke test (no model keys) and dry run (canned agent decisions, compose.demo-test.yaml)
# under the isolated asset-monitor-demo-test project.
test-demo: build
	./scripts/test-demo.sh

# The demo (A16) on a disposable VM only: see docs/demo.md.
demo-up: build
	./scripts/demo.sh up

# One demo step: STEP=1, 2, 3, merge-revert, 4, 5, merge-bump, php-inject or php-clean.
demo-step:
	./scripts/demo.sh step "$(STEP)"

demo-down:
	./scripts/demo.sh down

backup:
	./scripts/backup.sh $(if $(BACKUP),"$(BACKUP)")

restore:
	./scripts/restore.sh "$(BACKUP)"

reset-password:
	$(COMPOSE) --profile setup run --rm -e NUMEN_ADMIN_PASSWORD_FILE= bootstrap-operator python -m numen.cli reset-password

# The On-server agent: both binaries and SHA256SUMS in agent/dist/, and its Go checks.
agent:
	$(AGENT_GO) ./build.sh dist

# Also builds twice with fresh caches: the two must be byte-identical and match agent/dist/SHA256SUMS
# when it exists. TestDistBinaries then checks both binaries are static (no PT_INTERP, no DT_NEEDED).
test-agent:
	$(AGENT_GO) sh -c 'set -e; test -z "$$(gofmt -l .)"; go vet ./...; \
	  GOCACHE=/tmp/c1 ./build.sh /tmp/b1 >/dev/null; GOCACHE=/tmp/c2 ./build.sh /tmp/b2 >/dev/null; \
	  cmp /tmp/b1/SHA256SUMS /tmp/b2/SHA256SUMS; if [ -f dist/SHA256SUMS ]; then cmp /tmp/b1/SHA256SUMS dist/SHA256SUMS; fi; \
	  AGENT_DIST=/tmp/b1 go test -count=1 ./...'
