#!/bin/bash
set -euo pipefail

# Docker-compatible runtime command to use.
DOCKER_CMD="${DOCKER:-docker}"

# URL of the docker repository
REPOSITORY="registry-1.docker.io"

# Name of the organization
ORGANIZATION="freeandfair"

# Name of the docker image to run
IMAGE="de-ple-e2eviv"

# Fully qualified image reference
IMAGE_REF="$ORGANIZATION/$IMAGE:latest"

# Optional platform override (default: Docker native platform selection)
PLATFORM_OVERRIDE="${DE_PLE_PLATFORM:-}"

# Port mapping to expose Clafer IDE tools
PORT_OPTS="-p 8092:8092 -p 8093:8093 -p 8094:8094"

# Working directory in the container
WORKDIR="/work"

# Volume mapping. We map the current directory.
VOLUME="$PWD:$WORKDIR"

# Log into DockerHub only when read-only credentials are available.
if [[ -n "${DOCKER_READ_ONLY_TOKEN:-}" && -n "${DOCKER_READ_ONLY_TOKEN_USERNAME:-}" ]]; then
	echo "Logging into docker repository: $REPOSITORY with read-only token"
	printf '%s\n' "$DOCKER_READ_ONLY_TOKEN" \
		| "$DOCKER_CMD" login "$REPOSITORY" -u "$DOCKER_READ_ONLY_TOKEN_USERNAME" --password-stdin
else
	echo "No Docker read-only token provided; pulling anonymously."
fi

# Ensure the remote image is present.
if [[ -n "$PLATFORM_OVERRIDE" ]]; then
	"$DOCKER_CMD" pull --platform "$PLATFORM_OVERRIDE" "$IMAGE_REF"
else
	"$DOCKER_CMD" pull "$IMAGE_REF"
fi

# Print an informative message about volume mapping.
echo "Mapping current folder to /work inside the container."

# Run container interactively and automatically destroy it when exiting.
# Avoid empty-array expansion here because macOS Bash 3.2 + `set -u`
# treats `"${array[@]}"` as unbound when the array is empty.
if [[ -n "$PLATFORM_OVERRIDE" ]]; then
	"$DOCKER_CMD" run -it --rm --platform "$PLATFORM_OVERRIDE" $PORT_OPTS -v "$VOLUME" -w "$WORKDIR" "$IMAGE_REF"
else
	"$DOCKER_CMD" run -it --rm $PORT_OPTS -v "$VOLUME" -w "$WORKDIR" "$IMAGE_REF"
fi
