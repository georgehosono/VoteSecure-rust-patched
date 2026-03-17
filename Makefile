############################################################
# Top-level CI/CD/CV orchestration Makefile, © Free & Fair #
############################################################

SHELL := /bin/bash

# Docker-compatible command to use. Override with `DOCKER=podman`.
DOCKER ?= docker

# Optional container runtime platform (empty by default).
# Set this only when forcing a specific architecture is required, e.g.:
#   make IMAGE_PLATFORM=linux/amd64 <target>
IMAGE_PLATFORM ?=
USE_DOCKER ?= no
ifneq ($(filter yes YES true TRUE 1,$(DOCKER)),)
$(error DOCKER must name a container engine like docker or podman; use USE_DOCKER=yes to force container-backed execution)
endif
FORCE_DOCKER := $(if $(filter yes YES true TRUE 1,$(USE_DOCKER)),yes,)
PYTHON_BOOTSTRAP ?= no
CV_JOBS ?= 3

# Root and subdirectories.
ROOT_DIR := $(CURDIR)
TAMARIN_DIR := models/cryptography/tamarin
CRYPTOL_DIR := models/cryptography/cryptol
FEATURE_MODEL_DIR := models/feature-model
THREAT_MODEL_DIR := models/threat-model
ASSURANCE_DIR := assurance
RUST_DIR := implementations/rust/workspace

.PHONY: default all help ci cv cv-parallel clean \
	docker-pull docker-build \
	ci-python \
	ci-lando ci-feature-model ci-threat-model ci-tamarin ci-rust ci-assurance \
	cv-tamarin cv-cryptol cv-rust

# Default target.
default: help
all: help

help:
	@echo "Top-level orchestration targets:"
	@echo ""
	@echo "help (default)   - display this help page"
	@echo "ci               - run top-level CI checks (delegates to components)"
	@echo "cv               - run top-level CV checks (delegates to components)"
	@echo "cv-parallel      - run top-level CV checks in parallel (requires GNU Make >= 4.0; default: 3 jobs)"
	@echo "ci-python        - prepare local Python dependencies for CI/CV helpers"
	@echo "docker-pull      - pull required CI/CV Docker images"
	@echo "docker-build     - build all repository Docker images locally"
	@echo "clean            - clean generated artifacts across components"
	@echo ""
	@echo "Optional overrides:"
	@echo "  DOCKER=<docker|podman>"
	@echo "  IMAGE_PLATFORM=<platform> (optional; e.g. linux/amd64)"
	@echo "  USE_DOCKER=<yes|no> (default: no; force container-backed tools where supported)"
	@echo "  PYTHON_BOOTSTRAP=<yes|no> (default: no)"
	@echo "  CV_JOBS=<n> (default: 3; used by cv-parallel)"
	@echo ""
	@echo "Notes:"
	@echo "  - Lando/Clafer/feature-model and threat-model CI is delegated to"
	@echo "    localized Makefiles in those directories."
	@echo "  - Set USE_DOCKER=yes to force container-backed execution for"
	@echo "    Tamarin, Lando, and feature-model tooling where supported."
	@echo "  - Rust CI/CV is delegated to $(RUST_DIR)/Makefile."

# Delegate repository Docker image orchestration to docker/Makefile.
docker-pull:
	@$(MAKE) -C docker pull DOCKER="$(DOCKER)" \
		$(if $(strip $(IMAGE_PLATFORM)),IMAGE_PLATFORM="$(strip $(IMAGE_PLATFORM))",)

# Build all repository Docker images locally via docker/Makefile.
docker-build:
	@$(MAKE) -C docker build DOCKER="$(DOCKER)" \
		$(if $(strip $(IMAGE_PLATFORM)),IMAGE_PLATFORM="$(strip $(IMAGE_PLATFORM))",)

ci:
	@set -euo pipefail; \
	if [ "$(PYTHON_BOOTSTRAP)" = "yes" ]; then \
		echo "[info] PYTHON_BOOTSTRAP=yes; preparing Python environments"; \
		$(MAKE) ci-python; \
	fi
	@$(MAKE) ci-lando
	@$(MAKE) ci-feature-model PYTHON_BOOTSTRAP=$(PYTHON_BOOTSTRAP)
	@$(MAKE) ci-threat-model PYTHON_BOOTSTRAP=$(PYTHON_BOOTSTRAP)
	@$(MAKE) ci-tamarin
	@$(MAKE) ci-rust
	@$(MAKE) ci-assurance PYTHON_BOOTSTRAP=$(PYTHON_BOOTSTRAP)
	@echo "[info] top-level CI completed"

# Bootstrap local Python dependencies used by CI/CV-related helpers.
ci-python:
	@echo "[info] preparing feature-model Python environment"
	@$(MAKE) -C $(FEATURE_MODEL_DIR) python-venv
	@echo "[info] preparing threat-model Python environment"
	@$(MAKE) -C $(THREAT_MODEL_DIR) python-venv
	@echo "[info] preparing assurance Python environment"
	@$(MAKE) -C $(ASSURANCE_DIR) python-venv

# Lando CI delegates to localized targets.
ci-lando:
	@echo "[info] validating localized Lando models"
	@$(MAKE) -C models/domain-model/lando ci \
		DOCKER="$(DOCKER)" \
		IMAGE_PLATFORM="$(IMAGE_PLATFORM)" \
		USE_DOCKER="$(if $(FORCE_DOCKER),yes,no)"
	@$(MAKE) -C examples/needham-schroeder ci \
		DOCKER="$(DOCKER)" \
		IMAGE_PLATFORM="$(IMAGE_PLATFORM)" \
		USE_DOCKER="$(if $(FORCE_DOCKER),yes,no)"

# Feature model CI delegates to localized target.
ci-feature-model:
	@echo "[info] building feature model"
	@$(MAKE) -C $(FEATURE_MODEL_DIR) ci \
		DOCKER="$(DOCKER)" \
		IMAGE_PLATFORM="$(IMAGE_PLATFORM)" \
		USE_DOCKER="$(if $(FORCE_DOCKER),yes,no)" \
		PYTHON_BOOTSTRAP="$(PYTHON_BOOTSTRAP)"

# Threat model CI delegates to localized target.
ci-threat-model:
	@echo "[info] running threat model CI build"
	@$(MAKE) -C $(THREAT_MODEL_DIR) ci

# Tamarin CI delegates to localized target.
ci-tamarin:
	@echo "[info] running tamarin CI"
	@$(MAKE) -C $(TAMARIN_DIR) ci \
		DOCKER="$(DOCKER)" \
		IMAGE_PLATFORM="$(IMAGE_PLATFORM)" \
		USE_DOCKER="$(if $(FORCE_DOCKER),yes,no)"

# Rust CI delegates to localized target.
ci-rust:
	@$(MAKE) -C $(RUST_DIR) ci

# Assurance CI delegates to localized target.
ci-assurance:
	@echo "[info] running assurance CI"
	@$(MAKE) -C $(ASSURANCE_DIR) ci

cv: cv-tamarin cv-cryptol cv-rust
	@echo "[info] top-level CV completed"

cv-parallel:
	@case "$(MAKE_VERSION)" in \
		4.*|[5-9].*|[1-9][0-9].*) \
			echo "[info] running top-level CV in parallel with CV_JOBS=$(CV_JOBS)"; \
			$(MAKE) -j$(CV_JOBS) --output-sync=target cv \
				DOCKER="$(DOCKER)" \
				IMAGE_PLATFORM="$(IMAGE_PLATFORM)" \
				USE_DOCKER="$(USE_DOCKER)"; \
			;; \
		*) \
			echo "[error] cv-parallel requires GNU Make >= 4.0 for readable synchronized output;" >&2; \
			echo "[error] current MAKE_VERSION=$(MAKE_VERSION)." >&2; \
			echo "[error] Install a newer make (for example: brew install make) and run" >&2; \
			echo "[error] 'gmake cv-parallel', or use 'make cv'." >&2; \
			exit 2; \
			;; \
	esac

# Tamarin CV delegates to localized target.
cv-tamarin:
	@echo "[info] running Tamarin CV"
	@$(MAKE) -C $(TAMARIN_DIR) cv \
		DOCKER="$(DOCKER)" \
		IMAGE_PLATFORM="$(IMAGE_PLATFORM)" \
		USE_DOCKER="$(if $(FORCE_DOCKER),yes,no)"

# Cryptol CV delegates to localized target.
cv-cryptol:
	@echo "[info] running Cryptol CV"
	@$(MAKE) -C $(CRYPTOL_DIR) verify

# Rust CV delegates to localized target.
cv-rust:
	@$(MAKE) -C $(RUST_DIR) cv

clean:
	@echo "[info] cleaning subprojects"
	@$(MAKE) -C $(TAMARIN_DIR) clean
	@$(MAKE) -C $(FEATURE_MODEL_DIR) clean
	@$(MAKE) -C $(THREAT_MODEL_DIR) clean
	@$(MAKE) -C $(ASSURANCE_DIR) clean || true
	@$(MAKE) -C docker clean DOCKER="$(DOCKER)"
