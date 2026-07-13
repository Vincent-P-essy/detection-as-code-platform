.PHONY: validate test quality replay serve docker-build

PYTHON ?= python3
export PYTHONDONTWRITEBYTECODE := 1

validate:
	$(PYTHON) -m detection_platform validate

test:
	$(PYTHON) -m unittest discover -s tests -t . -v

quality:
	ruff check src tests scripts
	ruff format --check src tests scripts
	mypy src/detection_platform
	$(PYTHON) -m compileall -q src tests scripts
	$(PYTHON) scripts/safety_static_gate.py
	$(PYTHON) scripts/quality_gate.py
	$(PYTHON) scripts/verify_snapshot.py

replay:
	$(PYTHON) -m detection_platform replay --as-of 2026-07-13 --output-dir out/replay

serve:
	$(PYTHON) -m detection_platform serve --host 127.0.0.1 --port 8080

docker-build:
	docker build --tag detection-as-code-platform:local .
