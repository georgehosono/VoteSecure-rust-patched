################################################################################
# Threat Model Makefile, © 2025-26 Free & Fair                                 #
# Daniel M. Zimmerman, April 2026                                              #
# Possible commands: make [help|static|latex|pdf|html|view|ci|clean]           #
################################################################################

SHELL := /bin/bash

# Definitions

LATEXMK_CMD :=      latexmk --pdf
LATEX_INPUTS :=     ./latex_inputs
SRC_DIR :=          ./src
DIAGRAMS_DIR :=			./diagrams
PYTHON ?=           python3
VENV_DIR ?=         .venv
VENV_PYTHON :=      $(VENV_DIR)/bin/python3
PYTHON_REQUIREMENTS := requirements.txt
PYTHON_BOOTSTRAP ?= no
PYTHON_CMD :=       $(if $(wildcard $(VENV_PYTHON)),$(VENV_PYTHON),$(PYTHON))
PIP_CMD :=          $(PYTHON_CMD) -m pip
VIEW_CMD :=         $(PYTHON_CMD) -m nxt.model.view_cli
GEN_LATEX_CMD :=    $(PYTHON_CMD) -m nxt.model.generate_latex_inputs
GEN_HTML_CMD :=     $(PYTHON_CMD) -m nxt.model.generate_html
HTML_FILE :=        threat-model.html
BROWSER_CMD :=      open
THREAT_MODEL_DOC := threat-model

# Default target: show the help
all: help

# Display a brief help page listing possible targets.
help:
	@echo "Valid targets are:"
	@echo "help (default) - display this help page"
	@echo "latex          - generate all LaTeX inputs"
	@echo "pdf            - build the threat model PDF"
	@echo "html           - build the interactive threat model HTML"
	@echo "view           - run a smoketest of the command-line view of the model"
	@echo "python-requirements - install Python dependencies from $(PYTHON_REQUIREMENTS)"
	@echo "python-venv    - create $(VENV_DIR) and install Python dependencies"
	@echo "python-check   - verify local Python + required modules are available"
	@echo "python-ensure  - auto-bootstrap Python env when PYTHON_BOOTSTRAP=yes"
	@echo ""
	@echo "clean          - remove all generated files"
	@echo ""
	@echo "This Makefile assumes the diagrams are up to date, as they are"
	@echo "included in the repository. To rebuild the diagrams after changes,"
	@echo "use the Makefile in ${DIAGRAMS_DIR}"
	@echo ""

# Build static representations
static: pdf html

# Install threat-model Python dependencies using current interpreter.
python-requirements:
	@echo "installing threat model Python dependencies"
	${PIP_CMD} install -r ${PYTHON_REQUIREMENTS}

# Create isolated Python virtual environment and install dependencies.
python-venv:
	@echo "creating threat model Python virtual environment"
	${PYTHON} -m venv ${VENV_DIR}
	${VENV_PYTHON} -m pip install --upgrade pip
	${VENV_PYTHON} -m pip install -r ${PYTHON_REQUIREMENTS}

# Ensure dependencies needed by threat-model scripts are available.
python-check:
	@${PYTHON_CMD} -c "import anytree,jsonschema,natsort,networkx,pydantic,pyvis,yaml,tabulate" >/dev/null 2>&1 || \
		( echo "[error] missing threat-model Python dependencies"; \
		  echo "[hint] run 'make python-venv' (recommended) or 'make python-requirements'"; \
		  exit 1 )

# Ensure dependencies are available; optionally bootstrap venv.
python-ensure:
	@set -euo pipefail; \
	if [ "$(PYTHON_BOOTSTRAP)" = "yes" ]; then \
		echo "[info] PYTHON_BOOTSTRAP=yes; creating/updating Python venv"; \
		$(MAKE) python-venv; \
	else \
		$(MAKE) python-check; \
	fi

# CI target matching workflow behavior.
ci: python-ensure
	@echo "running threat model view smoke test"
	$(MAKE) view
	@echo "rendering threat model HTML and PDF"
	$(MAKE) html pdf

# Build the LaTeX inputs
latex:
	@echo "generating LaTeX inputs"
	mkdir -p ${LATEX_INPUTS}
	PYTHONPATH=${SRC_DIR} ${GEN_LATEX_CMD} --output ${LATEX_INPUTS}

# Build the PDF, including generating its dependencies
pdf: latex ${THREAT_MODEL_DOC}.tex references.bib
	@echo "generating threat model PDF"
	${LATEXMK_CMD} -halt-on-error -synctex=1 ${THREAT_MODEL_DOC}.tex

# Run a single smoketest of the command-line view of the model.
view:
	@echo "running an example view of the threat model"
	PYTHONPATH=${SRC_DIR} ${VIEW_CMD} -e attack -r "clash_attack_v2" -t

# Build the interactive HTML representation
html:
	@echo "generating interactive HTML representation"
	PYTHONPATH=${SRC_DIR} ${GEN_HTML_CMD} -o ${HTML_FILE}

# Clean the directory
clean:
	rm -rf ${LATEX_INPUTS}
	rm -f ${THREAT_MODEL_DOC}.pdf ${HTML_FILE}
	${LATEXMK_CMD} -bibtex-cond1 -C ${THREAT_MODEL_DOC}.tex

.PHONY: all help latex pdf html view ci clean \
	python-requirements python-venv python-check python-ensure
