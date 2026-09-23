# PhishGuard - common tasks.
#
#   make setup     install into a virtualenv
#   make all       train, evaluate, produce every deliverable
#   make up        run the whole stack in Docker
#
# Every target is a single documented command, so nothing in the report depends
# on a step that lives only in someone's shell history.

PY      ?= python3
VENV    ?= .venv
BIN     := $(VENV)/bin
N       ?= 12000
BUDGET  ?= 10
PORT    ?= 8000

.DEFAULT_GOAL := help
.PHONY: help setup install dev data train evaluate ablation attack card openapi \
        test test-fast lint fmt audit serve up down logs clean all deliverables

help:  ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- setup ---
setup: $(VENV)/.stamp  ## Create the virtualenv and install the project

$(VENV)/.stamp: pyproject.toml
	$(PY) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"
	@touch $@
	@echo "\nready. activate with: source $(VENV)/bin/activate"

install:  ## Install without the development extras
	$(PY) -m pip install -e .

dev: setup  ## Alias for setup

# ------------------------------------------------------------ pipeline ---
data: setup  ## Build the corpus and run the leakage audit
	$(BIN)/phishguard data --n $(N) --show-kinds

train: setup  ## Train a detector and register it
	$(BIN)/phishguard train --n $(N) --save

evaluate: setup  ## Produce the evaluation dossier and check the acceptance gates
	$(BIN)/phishguard evaluate --n $(N) --budget $(BUDGET)

ablation: setup  ## Full evaluation including the defence ablation (slow)
	$(BIN)/phishguard evaluate --n $(N) --budget $(BUDGET) --defense-ablation

attack: setup  ## Run the adversarial suite against the current model
	$(BIN)/phishguard attack --n $(N) --budget $(BUDGET) --sweep

card: setup  ## Regenerate the model card
	$(BIN)/phishguard card

openapi: setup  ## Export the OpenAPI document
	$(BIN)/python -c "from phishguard.service.app import export_openapi; \
	                  print(export_openapi('artifacts/reports/openapi.json'))"

# --------------------------------------------------------------- quality ---
test: setup  ## Run the full test suite
	$(BIN)/pytest -q

test-fast: setup  ## Unit and security tests only
	$(BIN)/pytest tests/unit tests/security -q

lint: setup  ## Lint
	$(BIN)/ruff check src tests scripts

fmt: setup  ## Format
	$(BIN)/ruff format src tests scripts

audit: setup  ## Scan dependencies for known vulnerabilities
	$(BIN)/pip-audit --strict

# --------------------------------------------------------------- runtime ---
serve: setup  ## Run the API locally
	$(BIN)/phishguard serve --port $(PORT)

up:  ## Build and start the full stack in Docker
	docker compose up --build -d
	@echo "\nconsole     http://localhost:$(PORT)"
	@echo "api docs    http://localhost:$(PORT)/docs"
	@echo "prometheus  http://localhost:9090"
	@echo "grafana     http://localhost:3000  (admin/admin)"
	@echo "\nthe first start trains a model; follow it with: make logs"

down:  ## Stop the stack
	docker compose down

logs:  ## Follow the API logs
	docker compose logs -f api

# ------------------------------------------------------------ aggregates ---
all: train evaluate card openapi  ## Train, evaluate and produce every artefact
	@echo "\nartefacts written to artifacts/reports/"

deliverables: test all ablation  ## Everything the submission needs (slow)
	@echo "\nsubmission artefacts:"
	@ls -1 artifacts/reports/

clean:  ## Remove generated artefacts and caches
	rm -rf artifacts .pytest_cache .ruff_cache .coverage htmlcov
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete
