# podman build \
#   --build-arg LABEL_CREATED="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
#   --build-arg LABEL_REVISION="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
#   --build-arg LABEL_AUTHOR="Your Name <email@example.com>" \
#   -t mint-crypto-env .

# ==========================================
# 1. OCI Metadata & Global Arguments
# ==========================================

# See https://github.com/opencontainers/image-spec/blob/main/annotations.md 
ARG BASE_REGISTRY="docker.io"
ARG BASE_IMAGE="library/ubuntu"
ARG BASE_IMAGE_TAG="24.04"

# ==========================================
# 2. Stage 1: The Build Environment (Builder)
# ==========================================
FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_IMAGE_TAG} AS builder

RUN set -e; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        wget \
        perl \
        zlib1g-dev \
        libtest-simple-perl \
        ca-certificates \
        pkg-config && \
    \
    echo "=== Fetching and Compiling OpenSSL 4.0.1 ===" && \
    cd /tmp && \
    wget --no-check-certificate https://github.com/openssl/openssl/releases/download/openssl-4.0.1/openssl-4.0.1.tar.gz && \
    tar -xf openssl-4.0.1.tar.gz && \
    cd openssl-4.0.1 && \
    ./config --prefix=/opt/openssl4 --openssldir=/opt/openssl4/ssl shared zlib && \
    make -j$(nproc) && \
    make install && \
    \
    echo "=== Fetching pqctoday-hsm Source ===" && \
    cd /tmp && \
    git clone --recursive https://github.com/pqctoday-org/pqctoday-hsm.git && \
    cd pqctoday-hsm && \
    \
    echo "=== Building SoftHSMv3 via CMake linking against OpenSSL 4 ===" && \
    mkdir build && cd build && \
    cmake .. \
        -DCMAKE_INSTALL_PREFIX=/opt/softhsmv3 \
        -DOPENSSL_ROOT_DIR=/opt/openssl4 \
        -DOPENSSL_LIBRARIES=/opt/openssl4/lib64 \
        -DOPENSSL_INCLUDE_DIR=/opt/openssl4/include && \
    make -j$(nproc) && \
    make install

# ==========================================
# 3. Stage 2: The Final Runtime Environment
# ==========================================
FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_IMAGE_TAG} AS runtime

# Re-declare ARGs for the OCI metadata layer
ARG LABEL_CREATED=""
ARG LABEL_AUTHOR=""
ARG LABEL_URL=""
ARG LABEL_DOCUMENTATION=""
ARG LABEL_SOURCE=""
ARG LABEL_VERSION="4.0.1"
ARG LABEL_REVISION=""
ARG LABEL_VENDOR=""
ARG LABEL_LICENSES="Apache-2.0"
ARG LABEL_TITLE="Mint-OpenSSL4-SoftHSMv3"
ARG LABEL_REF_NAME=""
ARG LABEL_DESCRIPTION="Multi-stage Container using OpenSSL v4 and SoftHSM v3"
ARG LABEL_BASE_DIGEST=""
ARG BASE_REGISTRY
ARG BASE_IMAGE
ARG BASE_IMAGE_TAG
ARG LABEL_BASE_NAME="${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_IMAGE_TAG}"

LABEL org.opencontainers.image.created="${LABEL_CREATED}" \
      org.opencontainers.image.authors="${LABEL_AUTHOR}" \
      org.opencontainers.image.url="${LABEL_URL}" \
      org.opencontainers.image.documentation="${LABEL_DOCUMENTATION}" \
      org.opencontainers.image.source="${LABEL_SOURCE}" \
      org.opencontainers.image.version="${LABEL_VERSION}" \
      org.opencontainers.image.revision="${LABEL_REVISION}" \
      org.opencontainers.image.vendor="${LABEL_VENDOR}" \
      org.opencontainers.image.licenses="${LABEL_LICENSES}" \
      org.opencontainers.image.title="${LABEL_TITLE}" \
      org.opencontainers.image.ref.name="${LABEL_REF_NAME}" \
      org.opencontainers.image.description="${LABEL_DESCRIPTION}" \
      org.opencontainers.image.base.digest="${LABEL_BASE_DIGEST}" \
      org.opencontainers.image.base.name="${LABEL_BASE_NAME}"

# Environment Setup (Linux Mint Spoofing)
RUN echo 'NAME="Linux Mint"\nVERSION="22.3 (Zena)"\nID=linuxmint\nID_LIKE="ubuntu debian"\nPRETTY_NAME="Linux Mint 22.3"\nVERSION_ID="22.3"\nVERSION_CODENAME=zena\nUBUNTU_CODENAME=noble' > /etc/os-release && \
    mkdir -p /etc/upstream-release && \
    echo 'DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=24.04\nDISTRIB_CODENAME=noble\nDISTRIB_DESCRIPTION="Ubuntu 24.04 LTS"' > /etc/upstream-release/lsb-release

# Install light dynamic runtime dependencies required to execute the binaries
RUN apt-get update && apt-get install -y --no-install-recommends \
        zlib1g \
        ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy ONLY the compiled stacks straight from the builder stage
COPY --from=builder /opt/openssl4 /opt/openssl4
COPY --from=builder /opt/softhsmv3 /opt/softhsmv3

# Symlink ensures you run "openssl4" to hit the isolated stack, preserving default "openssl"
RUN ln -s /opt/openssl4/bin/openssl /usr/local/bin/openssl4

# Set up runtime shared library links for dynamic executions
ENV LD_LIBRARY_PATH="/opt/softhsmv3/lib:/opt/openssl4/lib64:/opt/openssl4/lib:$LD_LIBRARY_PATH"

CMD ["/bin/bash"]