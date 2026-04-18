# SPDX-FileCopyrightText: 2022-23 Heiko Schaefer <heiko@schaefer.name>
# SPDX-License-Identifier: CC0-1.0

FROM fedora:38

# --- setup with gnupg-pkcs11-scd ---

RUN cd ~ \
 && dnf -y install softhsm gnupg-pkcs11-scd gnupg2 opensc openssl-pkcs11 pinentry \
      gnutls gnutls-utils expect \
      vim git procps findutils \
      sequoia-sq \
 && git clone https://github.com/alonbl/gnupg-pkcs11-scd/

COPY cli/ci/pkcs11-scd/gpg-agent.conf /root/.gnupg/
COPY cli/ci/pkcs11-scd/gnupg-pkcs11-scd.conf /root/.gnupg/

COPY cli/ci/pkcs11-scd/dummy-pinentry /root/
RUN chmod 0755 /root/dummy-pinentry

COPY cli/ci/pkcs11-scd/primary.exp /root/
COPY cli/ci/pkcs11-scd/subkeys.exp /root/

# initialize a new token in softhsm (under /tmp/softhsm/tokens/)
RUN cd /root/gnupg-pkcs11-scd/misc \
 && ./init-token.sh

# generate keys/certs
#   NOTE: enroll-token-openssl.sh works on fedora35, but not on fedora37
#      overwrite vars: "ALWAYS_AUTH=0" [enroll-token-gnutls.sh doesn't accept "1"]
RUN cd /root/gnupg-pkcs11-scd/misc \
 && echo "ALWAYS_AUTH=0" >> vars \
 && ./enroll-token-gnutls.sh

# --- show the resulting objects ---
ENV SOFTHSM2_CONF="/root/gnupg-pkcs11-scd/misc/softhsm2.conf"
ENV MODULE=/usr/lib64/pkcs11/libsofthsm2.so
ENV PIN=user

RUN pkcs11-tool --module $MODULE -O

# --- Import pkcs11 keys into gnupg ---
# see https://manpages.debian.org/bullseye/gnupg-pkcs11-scd/gnupg-pkcs11-scd.1.en.html#GNUPG_INTEGRATION

# Initialize GnuPG subsystems, get keygrips
RUN cd \
 && gpg --card-status \
 && echo "SCD LEARN" | gpg-connect-agent | grep KEY-FRIEDNLY > /root/keygrips \
 && cat /root/keygrips |grep "Dummy 01"|sed s/S\ KEY\-FRIEDNLY\ //|sed s/\ .*// > grip1 \
 && cat /root/keygrips |grep "Dummy 02"|sed s/S\ KEY\-FRIEDNLY\ //|sed s/\ .*// > grip2 \
 && cat /root/keygrips |grep "Dummy 03"|sed s/S\ KEY\-FRIEDNLY\ //|sed s/\ .*// > grip3

# Bind keys together as a public key in GnuPG
# Follow yubikey ykcs11 convention for slot usage (1: aut, 2: sig, 3: dec):
RUN cd \
 && expect primary.exp `cat grip2` \
 && gpg --list-keys pkcs11@example.org 2>/dev/null|grep ^\ \ \ \ \ |sed s/\ *// > pubfp \
 && expect subkeys.exp `cat pubfp` `cat grip3` `cat grip1` \
 && gpg --export -a > pkcs11.pub

# Test encrypt/decrypt and sign/verify operations on the card
RUN cd \
 && echo hello | sq encrypt --recipient-cert pkcs11.pub > encrypted \
 && gpg --decrypt encrypted \
 && echo foo | gpg --sign -a > signed \
 && sq verify --signer-cert pkcs11.pub signed

# --- reuse the card and cert from sequoia ---

COPY cli/ci/pkcs11-scd/yubikey.rs.diff /root/
RUN dnf -y install rustc cargo nettle-devel clang-devel pcsc-lite-devel patch

COPY . /build
WORKDIR /build
RUN cargo build

# --- Use SoftHSM card with our pkcs#11 backend ---

# Sign with HSM
RUN cargo run --bin opgpkcs11 -- --module $MODULE list > ~/serial.txt \
 && echo "hello world" | cargo run --bin opgpkcs11 -- --module $MODULE sign --serial `cat ~/serial.txt` --id 2 --pin user --cert ~/pkcs11.pub > ~/detach-sig \
 && echo "hello world" | sq verify --signer-cert ~/pkcs11.pub --detached ~/detach-sig

# Decrypt with HSM
RUN echo "hello world" | sq encrypt --recipient-cert ~/pkcs11.pub > ~/encrypted \
 && cat ~/encrypted | cargo run --bin opgpkcs11 -- --module $MODULE decrypt --serial `cat ~/serial.txt` --id 3 --pin user --cert ~/pkcs11.pub | grep -q "hello world"
