# podman build \
#   --build-arg LABEL_CREATED="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
#   --build-arg LABEL_REVISION="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
#   --build-arg LABEL_AUTHOR="Your Name <email@example.com>" \
#   -t mint-crypto-env:3stages-openssl4-softhsmv3 .

# ==========================================
# 1. OCI Metadata & Global Arguments
# ==========================================

# See https://github.com/opencontainers/image-spec/blob/main/annotations.md 
ARG BASE_REGISTRY="docker.io"
ARG BASE_IMAGE="library/ubuntu"
ARG BASE_IMAGE_TAG="24.04"

# ==========================================
# STAGE 1: OpenSSL 4 Builder
# ==========================================
FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_IMAGE_TAG} AS openssl-builder

RUN set -e; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        wget \
        perl \
        zlib1g-dev \
        ca-certificates && \
    \
    echo "=== Fetching and Compiling OpenSSL 4.0.1 ===" && \
    cd /tmp && \
    wget --no-check-certificate https://github.com/openssl/openssl/releases/download/openssl-4.0.1/openssl-4.0.1.tar.gz && \
    tar -xf openssl-4.0.1.tar.gz && \
    cd openssl-4.0.1 && \
    ./config --prefix=/opt/openssl4 --openssldir=/opt/openssl4/ssl shared zlib && \
    make -j$(nproc) && \
    make install

# ==========================================
# STAGE 2: SoftHSMv3 Builder
# ==========================================
FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_IMAGE_TAG} AS softhsm-builder

# Pull the compiled OpenSSL 4 artifacts from the first stage
COPY --from=openssl-builder /opt/openssl4 /opt/openssl4

RUN set -e; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        zlib1g-dev \
        ca-certificates \
        pkg-config && \
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
# STAGE 3: Latest OpenSC Builder (With ML-KEM Support)
# ==========================================
FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_IMAGE_TAG} AS opensc-builder
RUN set -e; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        autoconf \
        automake \
        libtool \
        pkg-config \
        git \
        gengetopt \
        libssl-dev \
        pcscd \
        libpcsclite-dev \
        ca-certificates \
        && \
    cd /tmp && \
    git clone https://github.com/OpenSC/OpenSC.git && \
    cd OpenSC && \
    ./bootstrap && \
    ./configure --prefix=/opt/opensc --sysconfdir=/etc/opensc --disable-reader-driver --disable-crypto && \
    make -j$(nproc) && \
    make install

# ==========================================
# STAGE 4: Final Runtime Environment (with Demo Script)
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
ARG LABEL_DESCRIPTION="Three-stage Container separating OpenSSL and SoftHSM compilation"
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

# Install dynamic runtime dependencies + opensc tools
RUN apt-get update && apt-get install -y --no-install-recommends \
        zlib1g \
        ca-certificates \
        && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy OpenSSL 4 from Stage 1
COPY --from=openssl-builder /opt/openssl4 /opt/openssl4

# Copy SoftHSMv3 from Stage 2
COPY --from=softhsm-builder /opt/softhsmv3 /opt/softhsmv3

# Copy OpenSC from Stage 3
COPY --from=opensc-builder /opt/opensc /opt/opensc

# Link opensc utility symlinks
RUN ln -s /opt/opensc/bin/pkcs11-tool /usr/local/bin/pkcs11-tool

# Link openssl4 command for side-by-side coexistency
RUN ln -s /opt/openssl4/bin/openssl /usr/local/bin/openssl4

# Set up SoftHSMv3 directory configurations
RUN mkdir -p /var/lib/softhsm/tokens/ && \
    echo "directories.tokendir = /var/lib/softhsm/tokens/" > /etc/softhsm2.conf

# Set up global environment paths
ENV LD_LIBRARY_PATH="/opt/softhsmv3/lib:/opt/openssl4/lib64:/opt/openssl4/lib:$LD_LIBRARY_PATH"
ENV SOFTHSM2_CONF="/etc/softhsm2.conf"

# ==========================================
# 4. Inject Automated PQC Test Demo Script
# ==========================================
# Inject Automated PQC Test Demo Script
RUN echo '#!/usr/bin/env bash\n\
set -e\n\
\n\
echo "======================================================="\n\
echo " 1. Initializing SoftHSMv3 Token Store (Slot 0)       "\n\
echo "======================================================="\n\
/opt/softhsmv3/bin/softhsm2-util --init-token --slot 0 --label "PQCToken" --pin 1234 --so-pin 4321\n\
\n\
echo -e "\\n======================================================="\n\
echo " 2. Listing Active Slots & Verifying Token            "\n\
echo "======================================================="\n\
pkcs11-tool --module /opt/softhsmv3/lib/softhsm/libsofthsmv3.so --list-slots\n\
\n\
echo -e "\\n======================================================="\n\
echo " 3. Generating Post-Quantum ML-KEM-768 Key Pair        "\n\
echo "======================================================="\n\
pkcs11-tool --module /opt/softhsmv3/lib/softhsm/libsofthsmv3.so \\\n\
            --login --pin 1234 \\\n\
            --token "PQCToken" \\\n\
            --keypairgen --key-type ML-KEM-768 \\\n\
            --label "my-pqc-key" --id 01\n\
\n\
echo -e "\\n======================================================="\n\
echo " 4. Listing Objects inside the PKCS#11 Store          "\n\
echo "======================================================="\n\
pkcs11-tool --module /opt/softhsmv3/lib/softhsm/libsofthsmv3.so --list-objects --token "PQCToken"\n\
echo -e "\\n=== Demo Completed Successfully ===\\n"\n\
' > /usr/local/bin/run-pqc-demo.sh && \
    chmod +x /usr/local/bin/run-pqc-demo.sh

# ==========================================
# 5. Inject Message of the Day (MOTD)
# ==========================================
RUN echo '\n\
echo -e "\\033[1;36m==================================================================\\033[0m"\n\
echo -e "\\033[1;32m Welcome to your Linux Mint 22.3 PQC Development Container!       \\033[0m"\n\
echo -e "\\033[1;36m==================================================================\\033[0m"\n\
echo -e " Available Stacks:"\n\
echo -e "  • OpenSSL Binary:     \\033[1;33mopenssl4\\033[0m ($(openssl4 version))"\n\
echo -e "  • SoftHSMv3 Library:  \\033[1;33m/opt/softhsmv3/lib/softhsm/libsofthsmv3.so\\033[0m"\n\
echo -e "  • OpenSC Utilities:   \\033[1;33mpkcs11-tool\\033[0m"\n\
echo -e ""\n\
echo -e "\\033[1;35m[TEST NOTICE]\\033[0m An automated Post-Quantum key generation test is available!"\n\
echo -e "To create a token store and generate an \\033[1;32mML-KEM-768\\033[0m key, run:"\n\
echo -e "      \\033[1;32mrun-pqc-demo.sh\\033[0m"\n\
echo -e "\\033[1;36m==================================================================\\033[0m\\n"\n\
' >> /etc/bash.bashrc

CMD ["/bin/bash"]