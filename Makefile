VENV ?= .venv
PY := $(VENV)/bin/python
SIGMA := $(VENV)/bin/sigma
PYTEST := $(VENV)/bin/pytest
RUFF := $(VENV)/bin/ruff

RULES := rules/sigma
BACKEND ?= loki

.PHONY: help setup lint validate test convert coverage check clean

help:
	@echo "Targets:"
	@echo "  setup     Create $(VENV) and install requirements"
	@echo "  lint      Run ruff over the repository"
	@echo "  validate  Validate Sigma rules with sigma-cli (sigma check)"
	@echo "  test      Run the rule and tooling test suite"
	@echo "  convert   Convert Sigma rules to the BACKEND query language (default: loki)"
	@echo "  coverage  Generate the ATT&CK for ICS coverage map"
	@echo "  check     lint + validate + test (what CI runs)"

$(VENV)/bin/activate: requirements.txt
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -r requirements.txt
	@touch $(VENV)/bin/activate

setup: $(VENV)/bin/activate

lint: setup
	$(RUFF) check .

validate: setup
	$(SIGMA) check $(RULES)

test: setup
	$(PYTEST)

convert: setup
	$(PY) pipelines/convert.py --backend $(BACKEND) --rules $(RULES)

coverage: setup
	$(PY) coverage/generate_coverage.py

check: lint validate test

clean:
	rm -rf $(VENV) .pytest_cache .ruff_cache pipelines/out coverage/out
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
