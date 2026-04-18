#!/bin/sh

ALGO=$1

set -e # Exit on error
set -x # Print executed commands

# ---

echo
echo "----------------------------"
echo
echo "Test run with algorithm: $ALGO"
echo

# Initialize a new token in softhsm

DIR=$(mktemp --directory) && echo "directories.tokendir = $DIR" > $SOFTHSM2_CONF

pkcs11-tool --init-token --module $MODULE --slot-index 0 --label TestToken --so-pin 12345678
pkcs11-tool --init-pin --login --so-pin 12345678 --pin 123456 --slot-index 0 --module $MODULE

pkcs11-tool --module $MODULE -O


# Use token

export SERIAL=`cargo run --bin opgpkcs11 -- --module $MODULE list`
cp cli/ci/keys/$ALGO.key /tmp/janus.key
rm --force /tmp/janus.cert && sq key extract-cert --output /tmp/janus.cert /tmp/janus.key

echo
echo "--- uploading keys"
echo

cargo run --bin opgpkcs11 -- --module $MODULE upload --serial $SERIAL --pin 123456 --id 2 --key /tmp/janus.key --pkt sign
cargo run --bin opgpkcs11 -- --module $MODULE upload --serial $SERIAL --pin 123456 --id 3 --key /tmp/janus.key --pkt encrypt

echo
echo "--- signing test"
echo

echo "hello world" | cargo run --bin opgpkcs11 -- --module $MODULE sign --serial $SERIAL --id 2 --pin 123456 --cert /tmp/janus.cert > /tmp/detached-sig
echo "hello world" | sq verify --signer-cert /tmp/janus.cert --detached /tmp/detached-sig

echo
echo "--- decryption test"
echo

echo "hello world" | sq encrypt --recipient-cert /tmp/janus.cert > /tmp/encrypted
cat /tmp/encrypted | cargo run --bin opgpkcs11 -- --module $MODULE decrypt --serial $SERIAL --id 3 --pin 123456 --cert /tmp/janus.cert | grep -q "hello world"
