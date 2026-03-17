#!/bin/bash
set -euo pipefail

# Docker-compatible runtime command to use.
DOCKER_CMD="${DOCKER:-docker}"

# Name of the Docker image to run
IMAGE="cpv-e2eviv"

# Working directory in the container
WORKDIR="/work"

# Map current host directory into the container
VOLUME="$PWD:$WORKDIR"

echo "Mapping current folder to $WORKDIR inside the container."

# Run container interactively and automatically remove it on exit
"$DOCKER_CMD" run -it --rm -v "$VOLUME" -w "$WORKDIR" "$IMAGE"
