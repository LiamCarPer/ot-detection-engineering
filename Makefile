VENV ?= .venv
PY := $(VENV)/bin/python
SIGMA := $(VENV)/bin/sigma
PYTEST := env -u PYTHONPATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 $(VENV)/bin/pytest
RUFF := $(VENV)/bin/ruff

RULES := rules/sigma
BACKEND ?= loki
RUST_DIR := tools
CARGO ?= cargo

.PHONY: help setup lint validate test rust convert convert-all deploy deploy-check suricata-check coverage emulate-validate metrics check clean

help:
	@echo "Targets:"
	@echo "  setup            Create $(VENV) and install requirements"
	@echo "  lint             Run ruff over the repository"
	@echo "  validate         Validate Sigma rules with sigma-cli (sigma check)"
	@echo "  test             Run the rule and tooling test suite"
	@echo "  rust             Format-check, lint and test the Rust protocol decoders"
	@echo "  convert          Convert Sigma rules to the BACKEND query language (default: loki)"
	@echo "  convert-all      Convert to loki, opensearch, splunk and sentinel"
	@echo "  deploy           Build the installable deployment bundle (deploy/)"
	@echo "  deploy-check     Fail if the committed bundle has drifted"
	@echo "  suricata-check   Run Suricata over the captures and refresh evidence (Docker)"
	@echo "  coverage         Generate the ATT&CK for ICS coverage map"
	@echo "  emulate-validate Validate the adversary emulation plan"
	@echo "  metrics          Generate coverage, replay emulation, compute metrics"
	@echo "  check            lint + validate + test + rust + deploy-check"

$(VENV)/bin/activate: requirements.txt
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -r requirements.txt
	@touch $(VENV)/bin/activate

setup: $(VENV)/bin/activate

lint: setup
	$(RUFF) check .

# sigma-cli's attacktag validator only knows ATT&CK Enterprise; ICS technique
# validation is enforced by tests/test_metadata.py against the pinned catalog.
validate: setup
	$(SIGMA) check -x attacktag $(RULES)

test: setup
	$(PYTEST)

rust:
	cd $(RUST_DIR) && $(CARGO) fmt --check
	cd $(RUST_DIR) && $(CARGO) clippy --workspace --all-targets -- -D warnings
	cd $(RUST_DIR) && $(CARGO) test --workspace

convert: setup
	$(PY) pipelines/convert.py --backend $(BACKEND) --rules $(RULES)

convert-all: setup
	$(PY) pipelines/convert.py --backend loki --rules $(RULES)
	$(PY) pipelines/convert.py --backend opensearch --rules $(RULES)
	$(PY) pipelines/convert.py --backend splunk --rules $(RULES)
	$(PY) pipelines/convert.py --backend sentinel --rules $(RULES)

deploy: setup
	$(PY) pipelines/deploy.py

deploy-check: setup
	$(PY) pipelines/deploy.py --check

suricata-check: setup deploy
	$(PY) tools/make_captures.py
	$(PY) tools/suricata_check.py

coverage: setup
	$(PY) coverage/generate_coverage.py

emulate-validate: setup
	$(PY) purple/runner/run_emulation.py --validate

# Replays the recorded lab run so metrics are reproducible without a lab.
metrics: setup
	$(PY) coverage/generate_coverage.py
	$(PY) purple/runner/run_emulation.py \
		--observations purple/emulation/lab-observations.json
	$(PY) metrics/compute.py

check: lint validate test rust deploy-check

clean:
	rm -rf $(VENV) .pytest_cache .ruff_cache pipelines/out coverage/out tools/target
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
