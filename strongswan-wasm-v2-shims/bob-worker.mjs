// bob-worker.mjs — runs in a Node worker thread with its OWN StrongswanV2
// instance (independent softhsmv3 state). Receives Alice's pubkey, does
// C_EncapsulateKey on this instance's HSM, ships ciphertext back.

import { parentPort } from 'node:worker_threads'
import StrongswanV2 from './dist/strongswan-v2-boot.js'

const events = []
const mod = await StrongswanV2({
    onVpnEvent: (type, payload) => {
        events.push({ type, payload })
        // Relay each HSM event up so the test harness can print a
        // unified timeline across both Workers.
        parentPort.postMessage({ kind: 'event', role: 'bob', type, payload })
    },
})

mod.ccall('wasm_vpn_boot', 'number', [], [])

parentPort.on('message', msg => {
    if (msg.kind !== 'alice_pub') return

    const alicePub = new Uint8Array(msg.bytes)
    const pubPtr = mod._malloc(alicePub.length)
    mod.HEAPU8.set(alicePub, pubPtr)

    const ctCap = 2048
    const ctPtr = mod._malloc(ctCap)

    const ctLen = mod.ccall(
        'wasm_vpn_kem_bob_encap',
        'number',
        ['number', 'number', 'number', 'number'],
        [pubPtr, alicePub.length, ctPtr, ctCap],
    )

    const secPtr = mod._malloc(64)
    const secLen = mod.ccall(
        'wasm_vpn_kem_get_secret', 'number',
        ['number', 'number'], [secPtr, 64],
    )
    const secret = Buffer.from(mod.HEAPU8.subarray(secPtr, secPtr + secLen))

    if (ctLen <= 0) {
        parentPort.postMessage({ kind: 'bob_error', ctLen })
        return
    }

    const ct = Buffer.from(mod.HEAPU8.subarray(ctPtr, ctPtr + ctLen))

    mod._free(pubPtr); mod._free(ctPtr); mod._free(secPtr)

    parentPort.postMessage({
        kind: 'bob_ct',
        bytes: ct,
        bobSecret: secret,
    })
})
