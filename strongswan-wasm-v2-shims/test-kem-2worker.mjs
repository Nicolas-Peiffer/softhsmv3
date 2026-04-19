// test-kem-2worker.mjs — Phase 3d: two WASM instances in separate Node
// Worker threads exchange ML-KEM-768 via byte messages. Independent
// softhsmv3 state on each side proves the softhsmv3 + strongswan-pkcs11
// WASM stack is truly cross-instance interoperable.
//
// Topology:
//   main thread (Alice) ──pub──▶  Worker thread (Bob)
//   main thread (Alice) ◀──ct─── Worker thread (Bob)
//   both independently derive 32-byte shared secret → must match.

import { Worker } from 'node:worker_threads'
import StrongswanV2 from './dist/strongswan-v2-boot.js'
import assert from 'node:assert'
import path from 'node:path'

const aliceMod = await StrongswanV2({
    onVpnEvent: (type, payload) => console.log(`[alice] ${type}: ${payload}`),
})
aliceMod.ccall('wasm_vpn_boot', 'number', [], [])

console.log('\n=== Alice: generate ML-KEM-768 keypair on her HSM ===')
const pubCap = 2048
const pubPtr = aliceMod._malloc(pubCap)
const pubLen = aliceMod.ccall(
    'wasm_vpn_kem_alice_init', 'number',
    ['number', 'number'], [pubPtr, pubCap],
)
assert.ok(pubLen > 0, `alice keygen failed (rv=${pubLen})`)
const alicePub = Buffer.from(aliceMod.HEAPU8.subarray(pubPtr, pubPtr + pubLen))
aliceMod._free(pubPtr)
console.log(`alice pub = ${alicePub.length} bytes`)

console.log('\n=== Spawn Bob in worker thread with its own WASM instance ===')
const bob = new Worker(path.join(import.meta.dirname, 'bob-worker.mjs'))

const bobCt = await new Promise((resolve, reject) => {
    bob.on('message', msg => {
        if (msg.kind === 'event') console.log(`[bob]   ${msg.type}: ${msg.payload}`)
        if (msg.kind === 'bob_ct') resolve(msg)
        if (msg.kind === 'bob_error') reject(new Error(`bob err ${msg.ctLen}`))
    })
    bob.on('error', reject)
    bob.postMessage({ kind: 'alice_pub', bytes: alicePub })
})

console.log(`bob ct = ${bobCt.bytes.length} bytes`)

console.log('\n=== Alice: decapsulate Bob\'s ciphertext ===')
const ctIn = new Uint8Array(bobCt.bytes)
const ctPtr = aliceMod._malloc(ctIn.length)
aliceMod.HEAPU8.set(ctIn, ctPtr)
const decapRv = aliceMod.ccall(
    'wasm_vpn_kem_alice_decap', 'number',
    ['number', 'number'], [ctPtr, ctIn.length],
)
aliceMod._free(ctPtr)
assert.ok(decapRv > 0, `alice decap failed (rv=${decapRv})`)

const secPtr = aliceMod._malloc(64)
const secLen = aliceMod.ccall(
    'wasm_vpn_kem_get_secret', 'number',
    ['number', 'number'], [secPtr, 64],
)
const aliceSecret = Buffer.from(aliceMod.HEAPU8.subarray(secPtr, secPtr + secLen))
aliceMod._free(secPtr)

console.log(`\nalice secret (${aliceSecret.length} B): ${aliceSecret.toString('hex').slice(0, 32)}...`)
console.log(`bob   secret (${bobCt.bobSecret.length} B): ${bobCt.bobSecret.toString('hex').slice(0, 32)}...`)

await bob.terminate()
aliceMod.ccall('wasm_vpn_shutdown', 'number', [], [])

assert.strictEqual(aliceSecret.length, 32)
/* Compare via hex so Buffer-vs-Uint8Array type difference doesn't trip
 * the equality check — both carry the same bytes. */
assert.strictEqual(
    aliceSecret.toString('hex'),
    Buffer.from(bobCt.bobSecret).toString('hex'),
    'alice and bob must derive identical 32-byte secrets across Workers',
)

console.log('\n✓ Phase 3d PASSED: two WASM instances in separate Worker threads')
console.log('  successfully derived identical ML-KEM-768 shared secrets')
console.log('  via softhsmv3 PKCS#11 — cross-instance interop verified.')
process.exit(0)
