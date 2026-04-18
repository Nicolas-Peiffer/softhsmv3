# SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
# SPDX-License-Identifier: CC0-1.0

FROM rust

RUN apt update -y -qq \
 && apt install -y -qq --no-install-recommends \
         nettle-dev libclang-dev libpcsclite-dev softhsm2 opensc sq

# Softhsm configuration
ENV MODULE=/usr/lib/softhsm/libsofthsm2.so
ENV SOFTHSM2_CONF=/tmp/softhsm.conf

# Pull in and build project sources
COPY . /build
WORKDIR /build
RUN cargo build

RUN for ALGO in rsa2048 rsa3072 rsa4096 nist-p256 nist-p384 nist-p521; do \
        sh cli/ci/softhsm/testrun.sh $ALGO; \
    done
