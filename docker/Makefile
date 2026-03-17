############################################################
# Docker image orchestration Makefile, © Free & Fair       #
############################################################

SHELL := /bin/bash

# Docker-compatible command to use. Override with `DOCKER=podman`.
DOCKER ?= docker

# Optional image platform selector, e.g.:
#   make pull IMAGE_PLATFORM=linux/amd64
#   make build IMAGE_PLATFORM=linux/amd64,linux/arm64
IMAGE_PLATFORM ?= linux/amd64,linux/arm64

# Standard repository image directories and published image references.
IMAGE_DIRS := cpv-e2eviv de-ple-e2eviv isabelle-e2eviv
TARGETS ?= $(IMAGE_DIRS)
PRUNE ?= no
IMAGE_REFS := \
	freeandfair/cpv-e2eviv:latest \
	freeandfair/de-ple-e2eviv:latest \
	freeandfair/isabelle-e2eviv:latest

.PHONY: default all help pull push build estimate-space clean

# Default target.
default: help
all: help

help:
	@echo "Valid build targets are:"
	@echo ""
	@echo "help (default) - display this help page"
	@echo "pull           - pull all repository Docker images"
	@echo "push           - push all repository Docker images to DockerHub"
	@echo "build          - build all repository Docker images locally"
	@echo "estimate-space - measure Docker storage usage while building TARGETS"
	@echo "clean          - run delegated clean targets for all image directories"
	@echo ""
	@echo "Optional overrides:"
	@echo "  DOCKER=<docker|podman>"
	@echo "  IMAGE_PLATFORM=<platform or comma-separated list>"
	@echo "  TARGETS='<space-separated image dirs>' (default: $(IMAGE_DIRS))"
	@echo "  PRUNE=<yes|no> (default: no; prune Docker data first)"

# Pull the published repository images.
pull:
	@echo "[info] pulling repository Docker images"
	@for dir in $(IMAGE_DIRS); do \
		echo "[info] make -C $$dir pull"; \
		$(MAKE) -C "$$dir" pull DOCKER="$(DOCKER)" IMAGE_PLATFORM="${IMAGE_PLATFORM}" || exit $$?; \
	done

# Push the locally built images to the repository.
push:
	@echo "[info] pushing repository Docker images"
	@for dir in $(IMAGE_DIRS); do \
		echo "[info] make -C $$dir push"; \
		$(MAKE) -C "$$dir" push DOCKER="$(DOCKER)" IMAGE_PLATFORM="$(IMAGE_PLATFORM)" || exit $$?; \
	done

# Build all repository Docker images locally via the per-image Makefiles.
build:
	@echo "[info] building standard repository Docker images locally"
	@for dir in $(IMAGE_DIRS); do \
		echo "[info] make -C $$dir image"; \
		$(MAKE) -C "$$dir" image DOCKER="$(DOCKER)" IMAGE_PLATFORM="$(IMAGE_PLATFORM)" || exit $$?; \
	done

# Empirically measure Docker storage usage while building selected images.
estimate-space:
	@DOCKER="$(DOCKER)" \
		IMAGE_PLATFORM="$(IMAGE_PLATFORM)" \
		TARGETS="$(TARGETS)" \
		PRUNE="$(PRUNE)" \
		./scripts/estimate-space.sh

# Clean delegated build artifacts for all repository Docker images.
clean:
	@echo "[info] cleaning Docker image artifacts"
	@for dir in $(IMAGE_DIRS); do \
		$(MAKE) -C "$$dir" clean || exit $$?; \
	done
