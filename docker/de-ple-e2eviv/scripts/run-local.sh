#!/bin/bash
set -euo pipefail

# Docker-compatible runtime command to use.
DOCKER_CMD="${DOCKER:-docker}"

# Name of the docker image to run
IMAGE="de-ple-e2eviv"

# Optional platform override (default: Docker native platform selection)
PLATFORM_OVERRIDE="${DE_PLE_PLATFORM:-}"

# Port mapping to expose Clafer IDE tools
PORT_OPTS="-p 8092:8092 -p 8093:8093 -p 8094:8094"

# Working directory in the container
WORKDIR="/work"

# Volume mapping. We map the current directory.
VOLUME="$PWD:$WORKDIR"

# Print an informative message about volume mapping.
echo "Mapping current folder to /work inside the container."

# Run container interactively and automatically destroy it when exiting.
# Avoid empty-array expansion here because macOS Bash 3.2 + `set -u`
# treats `"${array[@]}"` as unbound when the array is empty.
if [[ -n "$PLATFORM_OVERRIDE" ]]; then
	"$DOCKER_CMD" run -it --rm --platform "$PLATFORM_OVERRIDE" $PORT_OPTS -v "$VOLUME" -w "$WORKDIR" "$IMAGE"
else
	"$DOCKER_CMD" run -it --rm $PORT_OPTS -v "$VOLUME" -w "$WORKDIR" "$IMAGE"
fi
