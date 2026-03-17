############################################################################
# Multi-stage Dockerfile for the Free&Fair E2E-VIV DE/PLE Docker image     #
# (de-ple-e2eviv).                                                         #
############################################################################

# Stage 1: Build Chocosolver from source (Java/Maven)
FROM ubuntu:22.04 AS chocosolver-builder

RUN apt-get clean && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y build-essential git openjdk-17-jdk maven && \
    apt-get clean

RUN cd /tmp && \
    git clone https://github.com/GaloisInc/chocosolver.git && \
    cd chocosolver && \
    mvn install && \
    make install to=/opt/chocosolver

# Stage 2: Shared Haskell + Stack toolchain base
FROM ubuntu:22.04 AS haskell-stack-base

ARG TARGETARCH
ARG STACK_VERSION="3.9.3"
ARG STACK_SHA256_X86_64="bc45cf6e1d00910348dcceb510a469056f6d9c63997230f901c22cf997598b05"
ARG STACK_SHA256_AARCH64="c94360be1fe851c6e9f82089e93c8a4937ca536d42abccac908749e5a74220aa"

RUN apt-get clean && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y build-essential curl git ghc cabal-install ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Stack from a pinned official release tarball and verify checksum.
RUN set -eu; \
    case "${TARGETARCH}" in \
    amd64)  STACK_ARCH="x86_64"; STACK_SHA256="${STACK_SHA256_X86_64}" ;; \
    arm64)  STACK_ARCH="aarch64"; STACK_SHA256="${STACK_SHA256_AARCH64}" ;; \
    *) echo "Unsupported TARGETARCH for Stack: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    STACK_FILE="stack-${STACK_VERSION}-linux-${STACK_ARCH}.tar.gz"; \
    curl -fsSLO "https://github.com/commercialhaskell/stack/releases/download/v${STACK_VERSION}/${STACK_FILE}"; \
    echo "${STACK_SHA256}  ${STACK_FILE}" | sha256sum --check; \
    mkdir -p /opt/stack; \
    tar -xzf "${STACK_FILE}" -C /opt/stack --strip-components=1; \
    install -m 0755 /opt/stack/stack /usr/local/bin/stack; \
    rm -rf /opt/stack "${STACK_FILE}"; \
    stack --version

# Stage 3: Build Clafer and claferIG from source (Haskell/Stack + Java)
FROM haskell-stack-base AS haskell-builder

ARG CLAFER_REPO_URL="https://github.com/gsdlab/clafer.git"
ARG CLAFER_REPO_REF="refs/tags/0.5.1"
ARG CLAFERIG_REPO_URL="https://github.com/gsdlab/claferIG.git"
ARG CLAFERIG_REPO_REF="refs/tags/0.5.1"
ARG KODKOD_REPO_URL="https://github.com/emina/kodkod.git"
ARG KODKOD_REPO_REF="master"
ARG MINISATP_REPO_URL="https://github.com/emina/minisatp.git"
ARG MINISATP_REPO_REF="master"

# Ensure Java/Haskell tooling compiles with UTF-8 regardless of base locale.
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV JAVA_TOOL_OPTIONS="-Dfile.encoding=UTF-8"

RUN apt-get clean && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
    make \
    wget \
    unzip \
    openjdk-17-jdk \
    zlib1g-dev \
    libncurses5-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Clone Clafer repository and build from source using Stack
RUN cd /tmp && \
    git clone "$CLAFER_REPO_URL" clafer && \
    cd clafer && \
    git checkout "$CLAFER_REPO_REF" && \
    stack setup && \
    stack install --local-bin-path /opt/clafer/bin

# Verify Clafer binary exists
RUN /opt/clafer/bin/clafer --version

RUN cd /tmp && \
    git clone "$CLAFERIG_REPO_URL" claferIG && \
    cd claferIG && \
    git checkout "$CLAFERIG_REPO_REF" && \
    stack setup && \
    make && \
    STACK_ROOT="$(stack path --local-install-root)" && \
    mkdir -p /opt/claferig-dist/lib

# Build the Kodkod MiniSatProver JNI library from source for the current arch.
# Upstream claferIG only extracts prebuilt x86/x86_64 binaries from alloy4.2.jar,
# so we compile the Linux shared object ourselves to make arm64 usable.
RUN cd /tmp && \
    git clone "$KODKOD_REPO_URL" kodkod && \
    cd kodkod && \
    git checkout "$KODKOD_REPO_REF" && \
    cd /tmp && \
    git clone "$MINISATP_REPO_URL" minisatp && \
    cd minisatp && \
    git checkout "$MINISATP_REPO_REF" && \
    rm -rf /tmp/kodkod/jni/minisatp/minisatp && \
    cp -R /tmp/minisatp /tmp/kodkod/jni/minisatp/minisatp && \
    cd /tmp/kodkod/jni/minisatp && \
    JAVA_INCLUDE_DIR="$(dirname "$(find /usr/lib/jvm -name jni.h | head -n 1)")" && \
    test -n "$JAVA_INCLUDE_DIR" && \
    g++ -shared -std=gnu++03 -fPIC -w -O3 -ffloat-store \
    -D__STDC_LIMIT_MACROS -D__STDC_FORMAT_MACROS \
    -I. -I./minisatp \
    -I"$JAVA_INCLUDE_DIR" -I"$JAVA_INCLUDE_DIR/linux" \
    minisatp/Solver.C minisatp/Proof.C minisatp/File.C \
    kodkod_engine_satlab_MiniSatProver.cpp \
    -o /opt/claferig-dist/lib/libminisatprover.so && \
    cp /opt/claferig-dist/lib/libminisatprover.so /opt/claferig-dist/lib/libminisatproverx1.so

RUN cd /tmp/claferIG && \
    STACK_ROOT="$(stack path --local-install-root)" && \
    cp "$STACK_ROOT/bin/claferIG" /opt/claferig-dist/claferIG && \
    cp alloyIG.jar alloy4.2.jar /opt/claferig-dist/

RUN rm -rf /tmp/clafer /tmp/claferIG /tmp/kodkod /tmp/minisatp ~/.stack ~/.cache ~/.bashrc_stack

# Stage 4: Build Lando from source (Java/Maven)
FROM ubuntu:22.04 AS lando-builder

ARG LANDO_REPO_URL="https://github.com/GaloisInc/BESSPIN-Lando.git"
ARG LANDO_VERSION="db552ec74d4532611280693438207a72a23045b4"

RUN apt-get clean && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y git openjdk-17-jdk maven && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN cd /tmp && \
    git clone --branch develop --single-branch "$LANDO_REPO_URL" lando && \
    cd lando && \
    git reset --hard "$LANDO_VERSION" && \
    cd source/lando && \
    mvn clean package && \
    mkdir -p /opt/lando/lib && \
    cp target/lando-*-jar-with-dependencies.jar /opt/lando/lib/lando.jar

# Stage 5: Runtime base image with Clafer, Lando, and Chocosolver installed
FROM ubuntu:22.04 AS runtime-base

# Use Ubuntu 22.04 for libncurses5 compat (may be needed for future claferIG).
# Set environment variable for consistency across platforms.
ENV LC_ALL="en_US.UTF-8"
ENV LANG="en_US.UTF-8"

# Install only runtime dependencies (not build tools)
RUN apt-get clean && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    git \
    openjdk-17-jre \
    plantuml \
    python3-pip \
    python3 \
    locales \
    ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen && locale-gen en_US.UTF-8

# Create non-root user
RUN groupadd -g 1001 ple && \
    useradd -m -u 1001 -g 1001 ple

# Copy Clafer binaries from builder
COPY --from=haskell-builder /opt/clafer/bin/* /opt/clafer/bin/
RUN chmod +x /opt/clafer/bin/* && chown -R ple:ple /opt/clafer

# Copy Chocosolver JAR from builder
COPY --from=chocosolver-builder /opt/chocosolver/chocosolver.jar /opt/clafer/bin/
RUN chown -R ple:ple /opt/clafer/bin/chocosolver.jar

# Copy Lando launcher script and source-built runtime JAR
COPY resources/lando/bin /opt/lando/bin
COPY --from=lando-builder /opt/lando/lib /opt/lando/lib
RUN chmod +x /opt/lando/bin/lando && chown -R ple:ple /opt/lando

# Install minimal Python dependencies
RUN pip install --no-cache-dir jsons lark

# Set up PATH to include tools
ENV PATH="/opt/clafer/bin:/opt/lando/bin:$PATH"

# Stage 6: Final image
FROM runtime-base AS de-ple-e2eviv

ARG CLAFER_TOOLS_VER="clafer-tools-0.5.1"

USER root

RUN apt-get clean && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends npm libncurses5 wget unzip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build a classic clafer-tools style directory for compatibility.
RUN mkdir -p /opt/clafer/$CLAFER_TOOLS_VER
RUN cp /opt/clafer/bin/clafer /opt/clafer/$CLAFER_TOOLS_VER/
RUN cp /opt/clafer/bin/chocosolver.jar /opt/clafer/$CLAFER_TOOLS_VER/
ADD resources/chocosolver /opt/clafer/$CLAFER_TOOLS_VER/chocosolver
RUN chmod +x /opt/clafer/$CLAFER_TOOLS_VER/chocosolver

# Install claferIG artifacts (binary + jars + optional minisat libs).
COPY --from=haskell-builder /opt/claferig-dist/ /opt/clafer/$CLAFER_TOOLS_VER/
RUN test -f /opt/clafer/$CLAFER_TOOLS_VER/claferIG || \
    (echo "[error] claferIG missing after copy from haskell-builder" >&2; exit 1) && \
    chmod +x /opt/clafer/$CLAFER_TOOLS_VER/claferIG

# Install Clafer web IDEs.
RUN cd /opt/clafer && \
    git clone https://github.com/gsdlab/ClaferIDE.git && \
    cd ClaferIDE && \
    git submodule init && \
    git submodule update && \
    cd Server && \
    npm install

RUN cd /opt/clafer && \
    git clone https://github.com/gsdlab/ClaferConfigurator.git && \
    cd ClaferConfigurator && \
    git submodule init && \
    git submodule update && \
    cd Server && \
    npm install

RUN cd /opt/clafer && \
    git clone https://github.com/gsdlab/ClaferMooVisualizer.git && \
    cd ClaferMooVisualizer && \
    git submodule init && \
    git submodule update && \
    git submodule foreach git checkout develop && \
    cd Server && \
    npm install

# Clafer IDE compatibility path from legacy image.
RUN mkdir -p /home/clafertools040 && \
    ln -s /opt/clafer/$CLAFER_TOOLS_VER /home/clafertools040/bin && \
    chown -R ple:ple /home/clafertools040

# Start-up script for web IDE orchestration.
COPY resources/startup.sh /home/ple
RUN chown ple:ple /home/ple/startup.sh && chmod +x /home/ple/startup.sh

ENV PATH="/opt/clafer/$CLAFER_TOOLS_VER:/opt/clafer/bin:/opt/lando/bin:$PATH"

WORKDIR /home/ple
USER ple

ENTRYPOINT ["/home/ple/startup.sh"]
CMD ["/bin/bash"]
