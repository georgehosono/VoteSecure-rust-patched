################################################################################
# Parse all Lando models in this folder and translate to JSON/Markdown         #
# Possible commands: make [all|ci|clean]                                       #
################################################################################

SHELL := /bin/bash

# Docker fallback configuration for CI.
DOCKER ?= docker
PLE_IMAGE ?= freeandfair/de-ple-e2eviv:latest
IMAGE_PLATFORM ?=
DOCKER_PLATFORM_ARG := $(if $(strip $(IMAGE_PLATFORM)),--platform=$(strip $(IMAGE_PLATFORM)),)
USE_DOCKER ?= no
ifneq ($(filter yes YES true TRUE 1,$(DOCKER)),)
$(error DOCKER must name a container engine like docker or podman; use USE_DOCKER=yes to force container-backed execution)
endif
FORCE_DOCKER := $(if $(filter yes YES true TRUE 1,$(USE_DOCKER)),yes,)

# Docker invocation used when local lando is unavailable.
PLE_DOCKER_RUN = $(DOCKER) run --rm $(DOCKER_PLATFORM_ARG) -v "$(CURDIR)":/workspace -w /workspace $(PLE_IMAGE)

# Use the PLE Docker image unconditionally when USE_DOCKER=yes; otherwise
# prefer local lando and fall back to the Docker image when needed.
LANDO_CMD = $(if $(FORCE_DOCKER),$(PLE_DOCKER_RUN) lando,$(if $(shell command -v lando 2>/dev/null),lando,$(PLE_DOCKER_RUN) lando))

# We use a wildcard to detect all lando input files.
LANDO_FILES := $(wildcard *.lando)

# Corresponding JSON file for each detected lando file
JSON_FILES := $(patsubst %.lando,%.json,$(LANDO_FILES))

# Corresponding markdown file for each detected lando file
MD_FILES := $(patsubst %.lando,%.md,$(LANDO_FILES))

# ANSI escape sequences for fancier terminal output
ANSI_RESET   := \033[0m
ANSI_BOLD    := \033[1m
ANSI_BLACK   := \033[0;30m
ANSI_RED     := \033[0;31m
ANSI_GREEN   := \033[0;32m
ANSI_YELLOW  := \033[0;33m
ANSI_BLUE    := \033[0;34m
ANSI_MAGENTA := \033[0;35m
ANSI_CYAN    := \033[0;36m
ANSI_WHITE   := \033[0;37m

# Display a brief help page listing possible commands/targets.
help:
	@echo "Possible targets are:"
	@echo "help (default) - display this help page"
	@echo "all            - convert all .lando files to JSON and Markdown"
	@echo "ci             - validate all .lando files"
	@echo "clean          - remove generated JSON and Markdown files"

# By default, generate a JSON file for each present lando file.
all: $(JSON_FILES) $(MD_FILES)

# CI: validate all .lando files in this directory.
ci:
	@set -euo pipefail; \
	files="$(LANDO_FILES)"; \
	if [[ -z "$$files" ]]; then \
		echo "[info] no .lando files found in $(CURDIR)"; \
		exit 0; \
	fi; \
	for f in $$files; do \
		echo "[info] lando validate $$f"; \
		$(LANDO_CMD) validate "$$f"; \
	done

# Pattern rule to generate JSON files from lando sources.
%.json : %.lando
	@echo "Parsing $(ANSI_BOLD)$^$(ANSI_RESET) and generating $@ ..."
	$(LANDO_CMD) convert $< $@ --to json

# Pattern rule to generate markdown files from lando sources.
%.md : %.lando
	@echo "Parsing $(ANSI_BOLD)$^$(ANSI_RESET) and generating $@ ..."
	$(LANDO_CMD) convert $< $@ --to markdown

# Removes all dynamically generated JSON and markdown files.
clean:
	$(info Removing all dynamically generated files ...)
	rm -f $(JSON_FILES) $(MD_FILES)

.PHONY: help all ci clean
