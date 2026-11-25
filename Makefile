VENV ?= .venv
PY := $(VENV)/bin/python
SIGMA := $(VENV)/bin/sigma
PYTEST := env -u PYTHONPATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 $(VENV)/bin/pytest
RUFF := $(VENV)/bin/ruff

RULES := rules/sigma
BACKEND ?= loki
RUST_DIR := tools
CARGO ?= cargo

.PHONY: help setup lint validate test rust security-preflight security-api-check security-sast security-sca security-actions security-secrets security-ai-check security-sbom yara yara-check demo convert convert-all deploy deploy-check suricata-check loki-check decoder decoder-check collector collector-check baseline baseline-check conduit conduit-check stateful stateful-check perf perf-check fpr fpr-check lab-loki-check coverage emulate-validate purple purple-check case-study case-study-check health health-check metrics check clean

help:
	@echo "Targets:"
	@echo "  setup            Create $(VENV) and install requirements"
	@echo "  lint             Run ruff over the repository"
	@echo "  validate         Validate Sigma rules with sigma-cli (sigma check)"
	@echo "  test             Run the rule and tooling test suite"
	@echo "  rust             Format-check, lint and test the Rust protocol decoders"
	@echo "  security-preflight  Offline security governance and supply-chain checks"
	@echo "  security-api-check  Ingest API and AI triage security tests"
	@echo "  security-sast    Bandit over the Python surface"
	@echo "  security-sca     pip-audit dependency audit"
	@echo "  security-actions zizmor workflow analysis"
	@echo "  security-secrets gitleaks secret scan"
	@echo "  security-ai-check Ingest API and AI triage security tests"
	@echo "  security-sbom    CycloneDX SBOM (Docker)"
	@echo "  yara             Regenerate YARA evidence"
	@echo "  yara-check       Fail if the YARA evidence has drifted"
	@echo "  demo             Offline decoder -> Sigma rule -> SIEM query walkthrough"
	@echo "  convert          Convert Sigma rules to the BACKEND query language (default: loki)"
	@echo "  convert-all      Convert to loki, opensearch, splunk and sentinel"
	@echo "  deploy           Build the installable deployment bundle (deploy/)"
	@echo "  deploy-check     Fail if the committed bundle has drifted"
	@echo "  suricata-check   Run Suricata over the captures and refresh evidence (Docker)"
	@echo "  loki-check       Run the Loki ruler stack and refresh evidence (Docker)"
	@echo "  decoder          Regenerate decoder evidence"
	@echo "  decoder-check    Fail if the decoder evidence has drifted"
	@echo "  collector        Regenerate collector evidence"
	@echo "  collector-check  Fail if the collector evidence has drifted"
	@echo "  baseline         Regenerate behaviour-baseline evidence"
	@echo "  baseline-check   Fail if the behaviour-baseline evidence has drifted"
	@echo "  conduit          Regenerate conduit evidence"
	@echo "  conduit-check    Fail if the conduit evidence has drifted"
	@echo "  stateful         Regenerate stateful evidence"
	@echo "  stateful-check   Fail if the stateful evidence has drifted"
	@echo "  perf             Run decoder and replay benchmarks"
	@echo "  perf-check       Validate the committed performance evidence"
	@echo "  load-check       Sustained matcher load and bounded-queue drop test"
	@echo "  fpr              Regenerate the all-family false-positive report"
	@echo "  fpr-check        Fail if the all-family false-positive report has drifted"
	@echo "  lab-loki-check   Refresh the OT-Security-Lab ruler evidence (lab required)"
	@echo "  lab-benign-check Measure the network families on a lab PCAP (Docker required)"
	@echo "  lab-health-check Capture the live sensor-health rule proof"
	@echo "  lab-rules        Copy the generated Loki rules into the lab and reload"
	@echo "  coverage         Generate the ATT&CK for ICS coverage map"
	@echo "  emulate-validate Validate both adversary emulation plans"
	@echo "  purple           Regenerate the purple-team coverage evidence"
	@echo "  purple-check     Fail if the purple-team evidence has drifted"
	@echo "  case-study       Regenerate the lab alert-flood analysis"
	@echo "  case-study-check Fail if the committed analysis has drifted"
	@echo "  health           Regenerate the detection catalogue health report"
	@echo "  health-check     Fail if the catalogue or health report has drifted"
	@echo "  metrics          Generate coverage, replay emulation, compute metrics"
	@echo "  check            lint + validate + test + rust + proofs + deploy-check + purple-check + case-study-check + health-check"

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

yara: setup
	$(PY) tools/yara_check.py

yara-check: setup
	$(PY) tools/yara_check.py --check

security-api-check: setup
	$(PYTEST) tests/test_ingest_api.py tests/test_ingest_ai_security.py

security-sast: setup
	./security/run/sast.sh

security-sca: setup
	./security/run/sca.sh

security-actions: setup
	./security/run/actions.sh

security-secrets: setup
	./security/run/secrets.sh

security-ai-check: setup
	$(PYTEST) tests/test_ingest_api.py tests/test_ingest_ai_security.py

security-sbom: setup
	./security/run/sbom.sh

security-preflight: setup
	$(PY) tools/check_action_pins.py
	$(PY) coverage/security_coverage.py --check

security-coverage: setup
	$(PY) coverage/security_coverage.py

rust:
	cd $(RUST_DIR) && $(CARGO) fmt --check
	cd $(RUST_DIR) && $(CARGO) clippy --workspace --all-targets -- -D warnings
	cd $(RUST_DIR) && $(CARGO) test --workspace

demo: setup
	$(PY) tools/demo.py

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

loki-check: setup deploy
	$(PY) tools/loki_check.py

decoder: setup
	$(PY) tools/decoder_check.py

decoder-check: setup
	$(PY) tools/decoder_check.py --check

collector: setup
	$(PY) tools/collector_check.py

collector-check: setup
	$(PY) tools/collector_check.py --check

baseline: setup
	$(PY) tools/baseline_check.py

baseline-check: setup
	$(PY) tools/baseline_check.py --check

conduit: setup
	$(PY) tools/conduit_check.py

conduit-check: setup
	$(PY) tools/conduit_check.py --check

stateful: setup
	$(PY) tools/stateful_check.py

stateful-check: setup
	$(PY) tools/stateful_check.py --check

perf: setup
	$(PY) tools/perf_check.py

perf-check: setup
	$(PY) tools/perf_check.py --check

LOAD_EVENTS ?= /tmp/benign-events.jsonl

load-check: setup
	$(PY) tools/load_check.py --events "$(LOAD_EVENTS)" --target-eps 4000 --duration 5

fpr: setup
	$(PY) metrics/fpr.py

fpr-check: setup
	$(PY) metrics/fpr.py --check

lab-loki-check: setup
	$(PY) tools/lab_loki_check.py

LAB_DIR ?= /media/liamcarvajal/Storage/code/ot-security-lab
LAB_PCAP ?= $(LAB_DIR)/detection/logs/benign-24h.pcap

lab-benign-check: setup
	$(PY) tools/benign_lab_check.py --pcap "$(LAB_PCAP)"

lab-health-check: setup
	$(PY) tools/lab_health_check.py

lab-rules: deploy
	cp deploy/loki/rules/*.yaml "$(LAB_DIR)/siem/rules/"
	docker restart ot_loki

coverage: setup
	$(PY) coverage/generate_coverage.py

emulate-validate: setup
	$(PY) purple/runner/run_emulation.py --validate
	$(PY) purple/runner/run_emulation.py --plan purple/emulation/emulation-plan-2026-09-13.yaml --validate

purple: setup
	$(PY) purple/runner/run_emulation.py --observations purple/emulation/lab-observations.json --out deploy/evidence/purple

purple-check: setup
	$(PY) purple/runner/run_emulation.py --observations purple/emulation/lab-observations.json --out deploy/evidence/purple --check

case-study: setup
	$(PY) analysis/lab_case_study.py --input analysis/data/lab-2026-11-24 --out analysis/out
	$(PY) analysis/lab_case_study.py --input analysis/data/lab-2026-11-24 --out analysis/out --check

case-study-check: setup
	$(PY) analysis/lab_case_study.py --input analysis/data/lab-2026-11-24 --out analysis/out --check

health: setup
	$(PY) tools/detection_health.py

health-check: setup
	$(PY) tools/detection_health.py --check

parity-up: setup
	services/parity/setup.sh

engine-parity: setup
	$(PY) tools/engine_parity.py

# Replays the recorded lab run so metrics are reproducible without a lab.
metrics: setup
	$(PY) coverage/generate_coverage.py
	$(PY) purple/runner/run_emulation.py \
		--plan purple/emulation/emulation-plan-2026-09-13.yaml \
		--observations purple/emulation/lab-observations-2026-09-13.json \
		--out purple/results
	$(PY) purple/runner/run_emulation.py \
		--observations purple/emulation/lab-observations.json \
		--out deploy/evidence/purple
	$(PY) metrics/compute.py

check: lint validate test rust security-preflight yara-check decoder-check collector-check baseline-check conduit-check stateful-check perf-check fpr-check deploy-check purple-check case-study-check health-check

clean:
	rm -rf $(VENV) .pytest_cache .ruff_cache pipelines/out coverage/out tools/target
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
