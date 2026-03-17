############################################################
# Makefile for Needham-Schroeder example artifacts         #
############################################################

SHELL := /bin/bash

# Docker fallback configuration for Lando validation.
DOCKER ?= docker
PLE_IMAGE ?= freeandfair/de-ple-e2eviv:latest
IMAGE_PLATFORM ?=
DOCKER_PLATFORM_ARG := $(if $(strip $(IMAGE_PLATFORM)),--platform=$(strip $(IMAGE_PLATFORM)),)
USE_DOCKER ?= no
ifneq ($(filter yes YES true TRUE 1,$(DOCKER)),)
$(error DOCKER must name a container engine like docker or podman; use USE_DOCKER=yes to force container-backed execution)
endif
FORCE_DOCKER := $(if $(filter yes YES true TRUE 1,$(USE_DOCKER)),yes,)

LANDO_FILE := NeedhamSchroeder.lando

.PHONY: default help ci

default: help

help:
	@echo "Targets:"
	@echo "  help (default) - display this help page"
	@echo "  ci             - validate $(LANDO_FILE)"

ci:
	@set -euo pipefail; \
	if [[ -n "$(FORCE_DOCKER)" ]]; then \
		echo "[info] USE_DOCKER=yes; using $(PLE_IMAGE)"; \
		$(DOCKER) run --rm $(DOCKER_PLATFORM_ARG) \
			-v "$(CURDIR)":/workspace -w /workspace \
			$(PLE_IMAGE) lando validate "/workspace/$(LANDO_FILE)"; \
	elif command -v lando >/dev/null 2>&1; then \
		echo "[info] lando validate $(LANDO_FILE)"; \
		lando validate "$(LANDO_FILE)"; \
	else \
		echo "[info] lando not found locally; using $(PLE_IMAGE)"; \
		$(DOCKER) run --rm $(DOCKER_PLATFORM_ARG) \
			-v "$(CURDIR)":/workspace -w /workspace \
			$(PLE_IMAGE) lando validate "/workspace/$(LANDO_FILE)"; \
	fi
