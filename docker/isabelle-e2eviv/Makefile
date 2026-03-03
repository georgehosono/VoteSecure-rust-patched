################################################################################
# Makefile to build and deploy the isabelle-ci docker image - 2026 Frank Zeyda #
################################################################################
# Possible commands are: make [help|login|logout|image|pull|push|remove|clean]

# URL for the Docker repository (Docker Hub).
DOCKER_REPOSITORY := registry-1.docker.io

# Provider of the image (Docker Hub ID).
IMAGE_PROVIDER := freeandfair

# Name of the Docker image.
IMAGE := isabelle-e2eviv

# Image platform to use (linux/amd64 is a robust option for GitHub CI).
IMAGE_PLATFORM ?= "linux/amd64,linux/arm64"

# Docker-compatible command to use. A standard alternative is `podman`.
# Override via an environment variable (e.g., "make DOCKER=podman ...").
DOCKER := docker

# Different command line options for Podman, in the event that we
# need them. This was inspired by trying to fix a build problem, and
# even though it doesn't do anything right now it might in the future.
DOCKER_VERSION := $(shell $(DOCKER) --version)
DOCKER_OR_PODMAN := $(firstword $(DOCKER_VERSION))

# For Podman, we do not use Docker-specific attestation or SBOM options.
ifeq ($(DOCKER_OR_PODMAN), podman)
DOCKER_BUILD_ARGS=--platform=$(IMAGE_PLATFORM)
else
DOCKER_BUILD_ARGS=--platform=$(IMAGE_PLATFORM) --attest type=provenance,mode=max --attest type=sbom
endif

# The default target displays the help page.
default: help

# Display a brief help page listing possible commands/targets.
help:
	@echo "Possible commands/targets are:"
	@echo "make login  - log user into Docker Hub repository"
	@echo "make logout - log user out of Docker Hub repository"
	@echo "make image  - create $(IMAGE) image in local store; this is"
	@echo "              a multiplatform (AMD64 and ARM) image by default,"
	@echo "              but you can override this by setting
	@echo "              IMAGE_PLATFORM appropriately"
	@echo "make pull   - pull $(IMAGE) image from Docker Hub repository"
	@echo "make push   - push $(IMAGE) image to Docker Hub repository"
	@echo "make remove - remove $(IMAGE) image from local store"
	@echo "make clean  - remove all dynamically created files"
	@echo "make help   - display this help page"

# Log into Docker Hub Docker repository.
login:
	$(info [info] logging into Docker Hub repository)
	$(DOCKER) login $(DOCKER_REPOSITORY)

# Log out of Docker Hub Docker repository.
logout:
	$(info [info] Logging out of Docker Hub repository)
	$(DOCKER) logout $(DOCKER_REPOSITORY)

# Create Docker image in local store.
image:
	$(info [info] rebuilding $(IMAGE) Docker image ...)
	$(DOCKER) buildx build -t $(IMAGE) $(DOCKER_BUILD_ARGS) .

# Pull Docker image from Docker Hub repository.
pull: login
	$(DOCKER) pull $(IMAGE_PROVIDER)/$(IMAGE):latest

# Push Docker image to Docker Hub repository.
push: login
	$(DOCKER) image tag $(IMAGE) $(IMAGE_PROVIDER)/$(IMAGE):latest
	$(DOCKER) push $(IMAGE_PROVIDER)/$(IMAGE):latest

# Remove Docker image from local image store.
remove:
	$(info [info] removing $(IMAGE) image locally ...)
	$(DOCKER) rmi $(IMAGE)

# Clean up all dynamically generated files.
clean:
	$(info [info] cleaning up all dynamically generated files ...)
  # Nothing to do here for now!

.PHONY: default help login logout image pull push remove clean
