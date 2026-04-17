# Systems Operations & Integration Guide

Welcome to the SoftHSMv3 Operations Guide. This document is intended for Systems Administrators, DevOps Engineers, and SREs looking to integrate `libsofthsm3.so` natively into third-party infrastructure components like OpenSSL, NGINX, strongSwan, or Hyperledger Besu.

Because SoftHSMv3 was heavily modernized to support WebAssembly (WASM) and purely ephemeral cryptographic boundaries, its runtime architecture differs significantly from the legacy file-backed SoftHSMv2.

---

## 1. Critical Architectural Limitations

Before deploying SoftHSMv3 into a production pipeline, operators must understand the following structural shifts:

### A. Dual-Model Storage Architecture (RAM vs File-Backed)

* **WASM / Default Native (Memory Model):** By default, the token vault exists **exclusively in RAM**. If the host process attached to `libsofthsm3.so` terminates, the vault and all cryptographic materials inside it are instantly destroyed.
* **Persistent Native (File-Based Model):** You can compile the daemon utilizing `-DWITH_FILE_STORE=ON`. This natively attaches a persistent flat-file proxy mapped to `/var/lib/softhsm/tokens/` via `softhsm2.conf`. This behaves identically to SoftHSMv2, keeping Native Integration Testing parity intact and permanently saving CLI operations.

### B. Stateful Signature Crash-Resilience

For systems deploying XMSS or LMS operations, SoftHSMv3 actively flushes the `CKA_HSS_KEYS_REMAINING` attribute natively to disk (if `WITH_FILE_STORE=ON` is active) immediately upon generating a signature. This ensures the remaining state limits strictly survive unpredicted daemon crashes and subsequent process restarts.

### C. CLI Workflows Under the Memory Model

If you compile SoftHSMv3 **without** the flat-file persistence logic flag, using standalone command-line executions to configure the HSM will not work:

```bash
# THIS WILL CREATE A TOKEN THAT IMMEDIATELY DIES:
softhsm2-util --init-token --slot 0 --label "ProdToken"
pkcs11-tool --module libsofthsm3.so --keypairgen ...
```

When `pkcs11-tool` or `softhsm2-util` exits, the RAM boundary dies. If NGINX subsequently loads `libsofthsm3.so`, it boots into a completely blank, empty vault.

---

## 2. Daemonizing SoftHSMv3 via p11-kit

To use SoftHSMv3 with stateless third-party software (like a web server or short-lived scripts), you must wrap the library inside a dedicated, long-running daemon process. This daemon maps the RAM vault and serves it securely over a UNIX socket to your applications.

### 2.1 Register the module with p11-kit

Create `/etc/pkcs11/modules/softhsmv3.module`:

```ini
module: /usr/local/lib/libsofthsm3.so
managed: no
```

### 2.2 Start a persistent p11-kit server

```bash
# Submit to a systemd service for production use
p11-kit server --provider /usr/local/lib/libsofthsm3.so \
    --name "softhsmv3-daemon" \
    pkcs11:
```

### 2.3 Configure client processes

The `p11-kit server` will emit a `PKCS11_MODULE_PATH` environment variable pointing to its socket bridge. Inject this variable into NGINX, OpenVPN, or OpenSSL. Those applications will now transparently talk to the daemon's persistent RAM boundary over IPC rather than spinning up empty local vaults.

---

## 3. OpenSSL 3.x Provider Integration

SoftHSMv2 historically utilized `engine_pkcs11`, which is now strictly deprecated in OpenSSL 3.0+. SoftHSMv3 mandates **OpenSSL 3.6+** compliance, requiring the modern `pkcs11-provider` architecture.

SoftHSMv3 vendors the [Latchset pkcs11-provider](https://github.com/latchset/pkcs11-provider) at `src/vendor/latchset/` with ML-KEM and ML-DSA support already integrated. Build and install it directly from the repo rather than pulling the upstream package.

### 3.1 Build and install the vendored provider

```bash
cd src/vendor/pkcs11-provider
meson setup build
ninja -C build
ninja -C build install
```

If OpenSSL is installed to a non-system prefix, override the module directory:

```bash
meson setup build -Dopenssl_modulesdir=/opt/openssl-3.6/lib/ossl-modules
ninja -C build install
```

### 3.2 Update `openssl.cnf`

Add the provider to your global OpenSSL configuration:

```ini
[provider_sect]
default = default_sect
pkcs11  = pkcs11_sect

[pkcs11_sect]
module = /usr/lib64/ossl-modules/pkcs11.so
pkcs11-module-path = /usr/local/lib/libsofthsm3.so
```

### 3.3 PKCS#11 URIs

Once the OpenSSL provider is active, all 3.x compatible utilities (like NGINX) can reference key material purely by URI:

```text
ssl_certificate_key "pkcs11:token=ProdToken;object=MyPQCKey;type=private;";
```

---

## 4. StrongSwan IKEv2 Integration

The `strongswan-pkcs11/` adapter enables ML-KEM-768 key exchange and ML-DSA signing inside IKEv2 sessions without patching strongSwan core.

### Prerequisites

* strongSwan built with `--enable-pkcs11`
* `libsofthsm3.so` accessible to the strongSwan process
* Token initialized and keys pre-generated (or bootstrapped via the p11-kit daemon approach in §2)

### Configuration (`strongswan.conf`)

```ini
charon {
    plugins {
        pkcs11 {
            modules {
                softhsmv3 {
                    path = /usr/local/lib/libsofthsm3.so
                }
            }
        }
    }
}
```

### ML-KEM Key Exchange

The adapter's `pkcs11_kem_t` uses `C_EncapsulateKey` / `C_DecapsulateKey` (PKCS#11 v3.2 §5.17) for the IKEv2 KE payload. The `token=` keyword in the PKCS#11 URI selects which softhsmv3 token slot to use. No additional configuration is required — the adapter resolves the ML-KEM mechanism automatically when the peer negotiates a PQC key exchange group.

### ML-DSA Authentication

Generate an ML-DSA key pair in softhsmv3 and reference it in the IKEv2 peer connection:

```bash
# Generate ML-DSA-65 keypair inside softhsmv3
pkcs11-tool --module /usr/local/lib/libsofthsm3.so \
    --keypairgen --key-type ML-DSA:65 \
    --id 01 --label "ike-mldsa-auth" --token-label "IKEv2Token"
```

```ini
# swanctl.conf
connections {
    peer {
        local {
            auth = pubkey
            certs = "pkcs11:token=IKEv2Token;id=01;type=cert"
        }
    }
}
```

---

## 5. Java JCE Integration (Hyperledger Besu / JCA Apps)

The `JavaJCE/` module bridges standard JCA calls (`Signature`, `KeyAgreement`) to softhsmv3 PKCS#11 v3.2. This is required because the standard SunPKCS11 provider does not translate `"ML-DSA-65"` algorithm names to the `CKM_ML_DSA` (0x1d) mechanism constant without help.

### Deployment

Compile and install the JAR inside the patched JRE environment (see `JavaJCE/JavaJCESofthsmv3.md` for the full Docker build sequence), then register the provider at startup:

```java
Security.addProvider(new org.softhsmv3.jce.SoftHSMJCEProvider());
```

After registration, all `Signature.getInstance("ML-DSA-65")` and `KeyAgreement.getInstance("ML-KEM-768")` calls transparently route through `libsofthsm3.so`. No application code changes are required beyond provider registration.

### Key import for JCA

Keys generated via `pkcs11-tool` against the softhsmv3 token are immediately visible to SunPKCS11 and therefore to the JCE layer:

```bash
pkcs11-tool --module /usr/local/lib/libsofthsm3.so \
    --keypairgen --key-type ML-DSA:65 \
    --id 02 --label "besu-auth" --token-label "BesuToken"
```

---

## 6. Workarounds for Key Import (Memory Model Only)

If you chose to ignore `WITH_FILE_STORE=ON`, because keys are lost on restart, Ops architectures currently demand a "bootstrapper" process:

1. The `p11-kit` server starts.
2. A bootstrap script uses `pkcs11-tool` against the daemon socket to inject static keys or generate fresh keypairs.
3. The dependent application (NGINX, Besu, strongSwan) is subsequently launched.
