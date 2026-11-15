SHELL := /bin/sh
COMPOSE := ./scripts/compose.sh
CASE ?= all

.PHONY: init build up down logs check test test-unit test-integration test-runtime test-ui test-journey test-demo demo-up demo-step demo-down backup restore reset-password prune

init:
	./scripts/init.sh

build: init
	$(COMPOSE) --profile images build
	$(MAKE) prune

# Each rebuild leaves the previous Numen images untagged; remove only those, never other projects'.
prune:
	docker image prune -f --filter label=org.pruferva.asset-monitor.image=true

up: build
	$(COMPOSE) up -d --wait app worker scheduler runner-broker fetch-gateway
	$(COMPOSE) --profile setup run --rm bootstrap-operator

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs --tail=100 -f app worker scheduler runner-broker db

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
