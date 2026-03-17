# Isabelle Docker Image

This folder contains everything needed to build and run the Free & Fair Isabelle/HOL Docker image used for theorem-proving and document-building workflows. The current image installs `Isabelle2025-2` on Ubuntu 26.04, includes `latexmk` and a full TeX Live distribution, verifies the downloaded Isabelle release tarballs with pinned SHA-256 hashes, and prebuilds the `HOL` and `HOL-Algebra` heaps for CI use.

## Prerequisites

In order to rebuild the Docker image, you need the following:

- git and make
- [Docker](https://docker.com/) or Docker-compatible tools, such as [Podman](https://podman.io/)
- enough Docker memory for a large Isabelle build; the current Dockerfile notes that increasing Docker Desktop's memory limit (for example to 16 GB) may be necessary

To use or run the image from the [Free & Fair DockerHub](https://hub.docker.com/repository/docker/freeandfair/isabelle-e2eviv) repository, the only runtime prerequisite is Docker or a Docker-compatible tool.

## Building the Docker Image

The build process is simplified via the local *Makefile*. Simply typing `make` displays the help text; to build the image locally, use `make image`.

The following commands are supported:

```text
make login  - log user into Docker Hub repository
make logout - log user out of Docker Hub repository
make image  - create isabelle-e2eviv image in local store
make pull   - pull isabelle-e2eviv image from Docker Hub repository
make push   - push isabelle-e2eviv image to Docker Hub repository
make remove - remove isabelle-e2eviv image from local store
make clean  - remove all dynamically created files
make help   - display this help page
```

The image build honors `IMAGE_PLATFORM`, which defaults to `linux/amd64,linux/arm64`. To build only one platform, for example on Apple Silicon or when conserving build time, run:

```bash
make IMAGE_PLATFORM=linux/arm64 image
```

### Storage Requirements

A fresh multi-platform build of this image requires up to approximately 56 GB of local Docker storage from a clean state. Actual usage will vary by host, Docker version, and cache state.

## Deploying the Docker Image

Use `make push` after building the image locally. The current Makefile logs in to Docker Hub first and then pushes `freeandfair/isabelle-e2eviv:latest`. You must be a member of the [FreeAndFair](https://hub.docker.com/orgs/freeandfair) DockerHub organization with appropriate permissions to publish the image.

## Executing the Docker Image

Two helper scripts are provided in [`scripts/`](./scripts):

- [`run-local.sh`](./scripts/run-local.sh): run a locally built `isabelle-e2eviv` image.
- [`run-remote.sh`](./scripts/run-remote.sh): pull and run `freeandfair/isabelle-e2eviv:latest`.

Both scripts map the current working directory to `/work` inside the container so Isabelle sessions and other files can be used directly from the host. The scripts rely on Docker's native platform selection.

For `run-remote.sh`, Docker login is optional. If `DOCKER_READ_ONLY_TOKEN` and `DOCKER_READ_ONLY_TOKEN_USERNAME` are set, the script performs an authenticated pull; otherwise it pulls anonymously. Likewise, `make pull` is login-optional and uses the same token environment variables when provided.

You can also run the image manually, for example:

```bash
docker run -it --rm -v "$(PWD):/work" -w "/work" freeandfair/isabelle-e2eviv:latest
```

## Vulnerabilities Reported by Docker Scout

Docker Scout results vary over time as upstream base images and package feeds change. For a current snapshot, run `docker scout quickview isabelle-e2eviv:latest` or `docker scout quickview freeandfair/isabelle-e2eviv:latest`.
