# Continuous Integration, Deployment, and Verification (CI/CD/CV)

This document contains general information about the continuous integration (CI), continuous deployment (CD), and continuous verification (CV) practices of this project, and specific information about what artifacts are currently, and are planned to be, checked, generated, and verified using CI/CD/CV processes.

## Continuous Integration (CI)

Continuous integration checks that everything in the repository (that can be reasonably checked) has correct syntax, builds correctly without errors (and, depending on how pedantic we are for any given artifact, without warnings), and fulfills any other requirements of the project or the repository that can be automatically checked. Examples include ensuring that LaTeX documents can compile and generate PDFs, ensuring that Lando and Clafer models can be parsed, ensuring that Clafer models can generate instances, etc. CI processes are typically run on every commit to a pull request branch, and on every commit added to `main` or a release branch.

The artifacts that are currently subject to CI, the checks that are done, and the mechanisms by which that occurs are:

- Lando files (`*.lando`) are checked for syntactic validity, by running `lando validate` within our [PLE docker container](../docker/de-ple-e2eviv). This occurs for changed Lando files in pull request commits (via GitHub action workflow [Test Validity of Changed Lando Files](../.github/workflows/test-validity-of-changed-lando-files.yml)) and for all Lando files in the repository on every push to `main` (via GitHub action workflow [Test Validity of Lando Files](../.github/workflows/test-validity-of-lando-files.yml)).
- Clafer files (`*.cfr`) are checked for syntactic validity, by running `clafer` within our [PLE docker container](../docker/de-ple-e2eviv). This occurs for changed Clafer files in pull request commits (via GitHub action workflow [Test Validity of Changed Clafer Files](../.github/workflows/test-validity-of-changed-clafer-files.yml)) and for all Clafer files in the repository on every push to `main` (via GitHub action workflow [Test Validity of Clafer Files](../.github/workflows/test-validity-of-clafer-files.yml)).
- The CI target of the [feature model](../models/feature-model)'s [Makefile](../models/feature-model/Makefile) is built on pull request commits and on pushes to `main` that change anything within the feature model directory (via GitHub action workflow [Test Validity of Feature Model](../.github/workflows/test-validity-of-feature-model.yml)).
- The CI target of the [threat model](../models/threat-model)'s [Makefile](../models/threat-model/Makefile) is built on every commit that changes anything within the threat model's directory. This ensures that the threat model typechecks and that the static threat model documents can be built. The threat model diagrams are _not_ regenerated during continuous integration, because some of them require macOS and OmniGraffle to build, and their rendered versions are stored in the repository.
- The [Tamarin model](../models/cryptography/tamarin/) is checked for syntactic correctness (via GitHub action workflow [Test Validity of Tamarin Models](../.github/workflows/test-validity-of-tamarin-models.yml)) any time anything in its directory hierarchy changes.
- All buildable LaTeX documents in the repository are rebuilt on every commit that changes anything in them.
- All Cryptol code is checked for syntactic correctness and its properties are verified on every commit that changes Cryptol code.
- All Rust code is checked for syntactic correctness, and many other checks (e.g., lints, software supply chain verifications) are performed, on every commit that updates anything in the [Rust workspace](../implementations/rust/workspace/).
- Each Docker image that has changed, on any commit to `main`, is built to verify that its build process still completes successfully.

## Continuous Deployment (CD)

Continuous deployment (CD) ensures that a set of artifacts are generated and made available for download (rather than forcing individuals to regenerate the artifacts themselves). Such a set of artifacts for a project is called a "release". These generated artifacts may include rendered documents (e.g., PDFs from LaTeX sources, PDFs or Markdown documents from Lando sources), executable code, etc.

LaTeX documents and the threat model are currently subject to CD, and the repository for the [Free & Fair Coding Standards](https://github.com/FreeAndFair/CodingStandards), a multi-file LaTeX document, deploys a rendered version of the code standards to its [Latest release](https://github.com/FreeAndFair/CodingStandards/releases/tag/latest) every time a change to the document is pushed to its `main`.

## Continuous Verification and Validation (CV)

Continuous verification and validation (CV) ensures that the artifacts in the repository satisfy some correctness criteria, via execution of either generated or hand-written test suites and static formal verification routines. The artifacts on which we currently perform CV are:

- Cryptol implementations of cryptographic algorithms
- Tamarin descriptions of cryptographic protocols
- Rust implementations of the core library

## Docker Images

This repository currently uses the following Docker images in CI/CD/CV workflows:

- `freeandfair/cpv-e2eviv:latest`: tooling for cryptographic protocol verification and related checks
- `freeandfair/de-ple-e2eviv:latest`: rigorous digital engineering toolchain used for Lando/Clafer parsing and generation workflows
- `freeandfair/isabelle-e2eviv:latest`: Isabelle/HOL environment for theorem-proving workflows

While we have made every effort to make these Docker images multi-platform (supporting both `linux/amd64` and `linux/arm64` architectures), the status of multi-platform support currently differs by image:

- The CPV and Isabelle images support multi-platform builds, and all functionality works on both platforms.
- The DE/PLE image builds for both `linux/amd64` and `linux/arm64`; however, `claferIG`/Alloy instance generation is currently unreliable on `linux/arm64` (MiniSatProver assertion failure). `clafer`, `lando`, and `chocosolver` workflows work on both platforms.

When emulation is required on ARM hosts (e.g., Apple Silicon), use an explicit Docker platform argument to avoid ambiguity:

`--platform=linux/amd64`

The top-level `Makefile` supports this via the `IMAGE_PLATFORM` environment variable (i.e., `IMAGE_PLATFORM=linux/amd64` to build/use the AMD64 image).

Each Docker image build script is run on every merge to `main` that includes a change to that Docker image; however, there is no CD process to deploy the images automatically to DockerHub.

## Local Development: Top-Level CI/CV

For local parity with repository CI/CD/CV behavior, use the top-level [Makefile](../Makefile):

- `make ci` runs delegated CI checks across Lando, feature model, threat model, Tamarin, Rust, and assurance artifacts.
- `make cv` runs delegated CV checks on Tamarin, Cryptol, and Rust.
- `make cv-parallel` runs those same CV checks concurrently with synchronized per-target output, but it requires GNU Make >= 4.0 (for example Homebrew `gmake` on macOS); override `CV_JOBS=<n>` if you want a different parallelism level.
- `make docker-pull` pulls all required Docker images via the aggregator [docker/Makefile](../docker/Makefile).
- `make docker-build` builds all repository Docker images locally via [docker/Makefile](../docker/Makefile), which delegates to the image-specific `Makefile`s under `docker/`.
- `make clean` removes generated artifacts through delegated component clean targets.

On Apple Silicon, the practical upshot is that top-level local CI/CV remains fast and usable with native arm64 for current targets (`make ci`, `make cv`). If a workflow explicitly requires `claferIG`/Alloy instance generation, use `IMAGE_PLATFORM=linux/amd64` for that run.

Most component checks are delegated to localized `Makefile`s in the relevant directories. This keeps each artifact family's check logic near its source files while preserving a single project-level entry point.

### Local vs Container-backed Execution (`USE_DOCKER=yes`)

Some checks can run either with locally installed tools or with repository Docker images, with the following behavior:

1. If a local tool is present (for example `tamarin-prover`), run locally.
2. Otherwise, delegate to the appropriate Docker container.
3. Set `USE_DOCKER=yes` to force container-backed execution for artifacts that support it (for example, `USE_DOCKER=yes make ci` or `USE_DOCKER=yes make -C models/cryptography/tamarin cv`).
4. Use `DOCKER=<docker|podman>` to choose the container engine independently of that policy.

In order for this to work properly, the Docker containers must exist locally (for example, after `make docker-pull` or `make docker-build`).
