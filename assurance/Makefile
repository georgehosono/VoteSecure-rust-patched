###############################################
# Assurance Case Makefile, © Free & Fair      #
# Daniel M. Zimmerman, April 2026             #
###############################################

SHELL := /bin/bash

# Definitions

NXT_DIR :=          ../models/threat-model/src
SKELETON_DIR :=     ./advocate-project
PYTHON ?=           python3
VENV_DIR ?=         .venv
VENV_PYTHON :=      $(VENV_DIR)/bin/python3
PYTHON_REQUIREMENTS := scripts/requirements.txt
PYTHON_BOOTSTRAP ?= no
PYTHON_CMD :=       $(if $(wildcard $(VENV_PYTHON)),$(VENV_PYTHON),$(PYTHON))
PARSE_CMD :=        ${DB_DIR}/parse.py
GEN_SKELETON_CMD := PYTHONPATH="${PYTHONPATH}:${NXT_DIR}" $(PYTHON_CMD) scripts/generate_advocate_skeleton.py

# Default target: show the help
all: help

# Display a brief help page listing possible targets.
help:
	@echo "Valid build targets are:"
	@echo "help (default)        - display this help page"
	@echo ""
	@echo "skeleton         - (re)generate the AdvoCATE assurance case skeleton"
	@echo "skeleton_implied - (re)generate the AdvoCATE assurance case skeleton,"
	@echo "                   including implied security objectives (e.g., an"
	@echo "                   attack against objective C3.1 is also treated as an"
	@echo "                   attack against properties C3, C3.1.1, C3.1.2)"
	@echo ""
	@echo "    Note that the skeleton targets overwrite any manual changes to the"
	@echo "    skeleton files, but leave other AdvoCATE project files untouched."
	@echo ""
	@echo "update           - update the non-argument parts of the assurance case"
	@echo "                   skeleton from the latest threat model"
	@echo "update_implied   - update the non-argument parts of the assurance case"
	@echo "                   skeleton from the latest threat model, including"
	@echo "                   implied security objectives"
	@echo ""
	@echo "    The update targets update all the skeleton files except the argument,"
	@echo "    but leave other AdvoCATE project files untouched."
	@echo ""
	@echo "python-requirements - install Python dependencies from $(PYTHON_REQUIREMENTS)"
	@echo "python-venv         - create $(VENV_DIR) and install Python dependencies"
	@echo "python-check        - verify local Python + required modules are available"
	@echo "python-ensure       - auto-bootstrap Python env when PYTHON_BOOTSTRAP=yes"

# Install assurance Python dependencies using current interpreter.
python-requirements:
	@echo "installing assurance Python dependencies"
	$(PYTHON_CMD) -m pip install -r $(PYTHON_REQUIREMENTS)

# Create isolated Python virtual environment and install dependencies.
python-venv:
	@echo "creating assurance Python virtual environment"
	$(PYTHON) -m venv $(VENV_DIR)
	$(VENV_PYTHON) -m pip install --upgrade pip
	$(VENV_PYTHON) -m pip install -r $(PYTHON_REQUIREMENTS)

# Ensure dependencies and threat-model module path needed by skeleton generator are available.
python-check:
	@PYTHONPATH="${PYTHONPATH}:${NXT_DIR}" $(PYTHON_CMD) -c "import anytree,jsonschema,natsort,networkx,pydantic,pyvis,yaml,tabulate; import nxt.model.projection" >/dev/null 2>&1 || \
		( echo "[error] missing assurance Python dependencies or threat-model module path"; \
		  echo "[hint] run 'make python-venv' (recommended) or 'make python-requirements'"; \
		  exit 1 )
	@echo ""

# Ensure dependencies are available; optionally bootstrap venv.
python-ensure:
	@set -euo pipefail; \
	if [ "$(PYTHON_BOOTSTRAP)" = "yes" ]; then \
		echo "[info] PYTHON_BOOTSTRAP=yes; creating/updating Python venv"; \
		$(MAKE) python-venv; \
	else \
		$(MAKE) python-check; \
	fi

# Build the AdvoCATE skeleton files
skeleton:
	@echo "generating AdvoCATE skeleton"
	mkdir -p ${SKELETON_DIR}
	${GEN_SKELETON_CMD} ${SKELETON_DIR}

# Build the AdvoCATE skeleton files with implied security objectives included
skeleton_implied:
	@echo "generating AdvoCATE skeleton with implied security objectives"
	mkdir -p ${SKELETON_DIR}
	${GEN_SKELETON_CMD} --implied ${SKELETON_DIR}

# Build the non-argument AdvoCATE skeleton files
update:
	@echo "updating static parts of AdvoCATE skeleton"
	mkdir -p ${SKELETON_DIR}
	${GEN_SKELETON_CMD} --no-argument ${SKELETON_DIR}

# Build the non-argument AdvoCATE skeleton files with implied security
# objectives included
update_implied:
	@echo "updating static parts of AdvoCATE skeleton with implied security objectives"
	mkdir -p ${SKELETON_DIR}
	${GEN_SKELETON_CMD} --no-argument --implied ${SKELETON_DIR}

ci: python-ensure skeleton skeleton_implied update update_implied

.PHONY: all help skeleton skeleton_implied update update_implied ci \
	python-requirements python-venv python-check python-ensure
