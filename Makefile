.PHONY: help install lint check test convert all clean

help:
	@echo "BLUE-FORGE detection-as-code targets:"
	@echo "  make install   Install the pySigma toolchain (use a venv)"
	@echo "  make lint      Validate Sigma schema with 'sigma check'"
	@echo "  make test      Run rule policy tests (pytest)"
	@echo "  make convert   Compile every rule to Splunk SPL + Sentinel KQL"
	@echo "  make all       lint + test + convert (what CI runs)"
	@echo "  make clean     Remove build artifacts"

install:
	python -m pip install -r requirements.txt

lint:
	sigma check rules/

test:
	pytest -q

convert:
	python tools/convert.py

all: lint test convert

clean:
	rm -rf build/ .pytest_cache/
