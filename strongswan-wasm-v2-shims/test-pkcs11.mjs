// test-pkcs11.mjs — Phase 2 Checkpoint: statically-linked softhsmv3 visible
// through charon's pkcs11 plugin.
//
// Success criteria:
//   1. wasm_vpn_boot succeeds (carries Phase 1)
//   2. wasm_vpn_pkcs11_probe returns a non-negative slot count
//      (softhsmv3 may report 0 slots until a token is initialized —
//       that's still a "successful probe", not a crash)

import StrongswanV2 from './dist/strongswan-v2-boot.js'
import assert from 'node:assert'

const events = []
const mod = await StrongswanV2({
    onVpnEvent: (type, payload) => {
        events.push({ type, payload })
        console.log(`[event] ${type}: ${payload}`)
    },
})

console.log('Calling wasm_vpn_boot()...')
const bootRv = mod.ccall('wasm_vpn_boot', 'number', [], [])
assert.strictEqual(bootRv, 0, 'wasm_vpn_boot must return 0')

console.log('\nCalling wasm_vpn_pkcs11_probe()...')
const slotCount = mod.ccall('wasm_vpn_pkcs11_probe', 'number', [], [])
console.log(`wasm_vpn_pkcs11_probe returned ${slotCount}`)

console.log('\nCalling wasm_vpn_shutdown()...')
mod.ccall('wasm_vpn_shutdown', 'number', [], [])

assert.ok(slotCount >= 0, `expected non-negative slot count, got ${slotCount}`)
assert.ok(!events.some(e => e.type === 'error'), 'no error events expected')

console.log('\n✓ Phase 2 Checkpoint 2 PASSED')
console.log(`  softhsmv3 statically linked and responding (${slotCount} slot(s))`)
process.exit(0)
