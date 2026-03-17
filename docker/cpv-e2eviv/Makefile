################################################################################
# Makefile to build and deploy the Free & Fair CPV Docker image, © Free & Fair #
################################################################################

# Organization within the Docker repository to push to.
DOCKER_ORGANIZATION := freeandfair

# Docker repository endpoint.
DOCKER_REPOSITORY := registry-1.docker.io

# Name of the Docker image to be created.
IMAGE := cpv-e2eviv

# Image platform(s) to build. Override, for example:
#   make IMAGE_PLATFORM=linux/arm64 image
# By default this builds a multi-platform image.
IMAGE_PLATFORM ?= linux/amd64,linux/arm64

# Docker-compatible command to use.  A standard alternative is `podman`.
# Override via an environment variable (e.g., "make DOCKER=podman ...").
DOCKER ?= docker

# We use different build arguments depending on the container engine.
DOCKER_VERSION := $(shell $(DOCKER) --version)
DOCKER_OR_PODMAN := $(firstword $(DOCKER_VERSION))
ifeq ($(DOCKER_OR_PODMAN), podman)
DOCKER_BUILD_ARGS := --platform=$(IMAGE_PLATFORM)
else
# For Docker, we use Docker-specific attestation and SBOM options
DOCKER_BUILD_ARGS := --platform=$(IMAGE_PLATFORM) --attest type=provenance,mode=max --attest type=sbom
endif

# Default target: help
all: help

# Display a brief help page listing possible commands/targets.
help:
	@echo "This Makefile supports the following targets:"
	@echo ""
	@echo "help (default) - display this help page"
	@echo "login          - log user into DockerHub repository"
	@echo "logout         - log user out of DockerHub repository"
	@echo "image          - create $(IMAGE) image"
	@echo "                 (default platforms: $(IMAGE_PLATFORM))"
	@echo "                 (override IMAGE_PLATFORM=linux/arm64 for ARM builds)"
	@echo "save           - save $(IMAGE) image to a tar file"
	@echo "pull           - pull cpv-e2eviv image from DockerHub repository"
	@echo "push           - publish a single manifest image for IMAGE_PLATFORM"
	@echo "remove         - remove $(IMAGE) image from local store"
	@echo "clean          - remove all dynamically created files"

# Log into DockerHub.
login:
	$(info [info] logging into DockerHub)
	$(DOCKER) login

# Log out of DockerHub.
logout:
	$(info [info] Logging out of DockerHub)
	$(DOCKER) logout

# Create Docker image.
image:
	$(info [info] rebuilding $(IMAGE) Docker image ...)
	$(DOCKER) buildx build --load -t $(IMAGE) . $(DOCKER_BUILD_ARGS)

# Save Docker image locally to a .tar file.
save:
	$(info [info] saving Docker image to $(IMAGE).tar ...)
	$(DOCKER) save -o $(IMAGE).tar $(IMAGE)

# Pull Docker image from DockerHub repository.
# If read-only credentials are present, use them; otherwise pull anonymously.
pull:
	@if [ -n "$$DOCKER_READ_ONLY_TOKEN" ] && [ -n "$$DOCKER_READ_ONLY_TOKEN_USERNAME" ]; then \
		echo "[info] authenticating to DockerHub with read-only token"; \
		printf '%s\n' "$$DOCKER_READ_ONLY_TOKEN" | \
			$(DOCKER) login $(DOCKER_REPOSITORY) -u "$$DOCKER_READ_ONLY_TOKEN_USERNAME" --password-stdin; \
	else \
		echo "[info] no Docker read-only token provided; pulling anonymously"; \
	fi
	$(DOCKER) pull $(DOCKER_ORGANIZATION)/$(IMAGE):latest

# Push Docker image to DockerHub repository.
push: login
	$(DOCKER) buildx build \
		-t $(DOCKER_ORGANIZATION)/$(IMAGE):latest \
		--push \
		. $(DOCKER_BUILD_ARGS)

# Remove Docker image from local image cache / store.
remove:
	$(info [info] removing $(IMAGE) image locally ...)
	$(DOCKER) rmi $(IMAGE)

# Clean up all dynamically generated files.
clean:
	$(info [info] cleaning up all dynamically generated files ...)
	rm -f $(IMAGE).tar

PHONY: all help login logout image save pull push remove clean
