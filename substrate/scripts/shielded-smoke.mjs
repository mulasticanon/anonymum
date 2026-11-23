// Submits a real Groth16-proved shielded transaction to a local dev node, so
// the proof is verified inside the WebAssembly runtime. DEV ONLY: the keys
// come from a public seed and the spent note's secrets are in the repository.
//
//   cargo build --release --locked -p anonymum-shielded-circuit --example dev_tool   (repository root)
//   bash substrate/scripts/run-node.sh                                               (WSL)
//   cd substrate/scripts && node shielded-smoke.mjs

import { ApiPromise, WsProvider } from '@polkadot/api';
import { compactAddLength, u8aConcat, u8aToHex } from '@polkadot/util';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const TOOL = resolve(here, '../../target/release/examples', process.platform === 'win32' ? 'dev_tool.exe' : 'dev_tool');
const [CHAIN_ID, VERSION, WINDOW, FEE] = [4242, 1, 60, 1000n];
const SPEC_VERSION = 10;
const POW_BITS = 16;

function check(ok, message) {
  if (!ok) {
    console.error(`  FAILED: ${message}`);
    process.exit(1);
  }
  console.log(`  ok: ${message}`);
}

const provider = new WsProvider('ws://127.0.0.1:9944');
const api = await ApiPromise.create({ provider, noInitWarn: true });
const q = api.query.anonymumShielded;
const nowSecs = async () => Math.floor(Number((await api.query.timestamp.now()).toBigInt()) / 1000);
const head = async () => (await api.rpc.chain.getHeader()).number.toNumber();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * A general transaction (extrinsic format 5), which Polkadot.js does not
 * build itself. No signer, so nothing identifies a sender:
 * 0x45 (format 5, general), 0x00 (extension version), then the extensions
 * that carry data, in pipeline order: era 0x00 (immortal), nonce 0, tip 0.
 */
function general(t, note = t.note, proof = t.proof, powNonce = t.powNonce) {
  const method = api.tx.anonymumShielded.submitShielded(
    t.root, t.nullifiers, t.commitments, t.admission, t.notBefore, t.notAfter, t.coin, note, proof, powNonce,
  ).method.toU8a();
  return u8aToHex(compactAddLength(u8aConcat(new Uint8Array([0x45, 0x00, 0x00, 0x00, 0x00]), method)));
}

const send = (hex) => provider.send('author_submitExtrinsic', [hex]);

/** The node's refusal message, or null if it accepted the transaction. */
async function refused(hex) {
  try {
    await send(hex);
    return null;
  } catch (e) {
    return e.message;
  }
}

/** The `Shielded` event of the first block after `from` that has one. */
async function shieldedEvent(from) {
  for (let tries = 0; tries < 60; tries++) {
    const top = await head();
    for (let n = from + 1; n <= top; n++) {
      const at = await api.at(await api.rpc.chain.getBlockHash(n));
      const events = await at.query.system.events();
      const found = events.find(({ event: e }) => e.section === 'anonymumShielded' && e.method === 'Shielded');
      if (found) return { found, failed: events.find(({ event: e }) => e.method === 'ExtrinsicFailed') };
    }
    await sleep(1000);
  }
  return {};
}

console.log(`Connected, spec_version ${api.runtimeVersion.specVersion}`);
check(api.runtimeVersion.specVersion.toNumber() === SPEC_VERSION, `runtime spec_version is ${SPEC_VERSION}`);
check(api.consts.anonymumShielded.powDifficulty.toNumber() === POW_BITS, `the runtime requires ${POW_BITS} bits of proof of work`);
check((await q.baseFee()).toBigInt() === FEE, 'dev base fee is in genesis');
check((await q.nextIndex()).toNumber() === 4, 'the tree starts with the 4 fixture leaves');
const startRoot = (await q.currentRoot()).toHex();

// Genesis has timestamp 0, so wait for a real block time before proving.
while ((await nowSecs()) === 0) await sleep(1000);
// Prove for a window with time left, so the block lands inside it.
while (WINDOW - ((await nowSecs()) % WINDOW) < 30) await sleep(2000);
const started = Date.now();
const t = JSON.parse(execFileSync(TOOL, ['tx', CHAIN_ID, VERSION, await nowSecs(), WINDOW, POW_BITS].map(String), { encoding: 'utf8' }));
console.log(`\nProved a Transfer in ${Date.now() - started} ms (includes regenerating the dev keys).`);
console.log(`Solved its ${t.powBits}-bit proof of work in ${(t.powMicros / 1000).toFixed(2)} ms (nonce ${t.powNonce}).`);
check(t.root === startRoot, 'proved against the on-chain root');

// Refusals by authorization, before anything is pooled.
const tampered = `0x${t.note.startsWith('0xff') ? '00' : 'ff'}${t.note.slice(4)}`;
let why = await refused(general(t, tampered));
check(why?.includes('Custom error: 13'), `a tampered stranger note fails the proof of work (${why})`);
why = await refused(general(t, t.note, t.rerandomised));
check(why?.includes('Custom error: 13'), `a solved nonce does not carry over to other proof bytes (${why})`);
why = await refused(general(t, t.note, t.wrongProof, t.wrongProofPowNonce));
check(why?.includes('Custom error: 12'), `a wrong proof with valid work is refused by the pairing (${why})`);
const garbage = `0x${'ff'.repeat(192)}`;
why = await refused(general(t, t.note, garbage));
check(why?.includes('Custom error: 11'), `the pool refuses malformed proof bytes (${why})`);
why = await refused(general(t, t.note.slice(0, -2)));
check(why !== null, `the pool refuses a short note (${why})`);

const before = await head();
await send(general(t));
check(true, 'the pool accepted the general transaction, with no signer');
// Same nullifiers, different proof bytes: refused while the first is pooled
// (a tag conflict) or once it is included (a spent nullifier).
why = await refused(general(t, t.note, t.rerandomised, t.rerandomisedPowNonce));
check(why !== null, `a re-randomised copy with its own work is refused at once (${why})`);

const { found, failed } = await shieldedEvent(before);
check(found && !failed, 'the WebAssembly runtime verified the proof and accepted the transaction');
check(!JSON.stringify(found.event.data.toJSON()).includes(t.proof.slice(2)), 'the event does not carry the proof');

const [sighash, noteHash, windowStart] = found.event.data;
check((await q.nextIndex()).toNumber() === 7, 'three leaves were appended');
const newRoot = (await q.currentRoot()).toHex();
check(newRoot !== startRoot && (await q.acceptedRoots(newRoot)).isSome, 'the new root is accepted');
for (const n of t.nullifiers) check((await q.nullifiers(n)).isSome, 'nullifier recorded');
check((await q.burnedFees()).toBigInt() === FEE / 2n && (await q.nodeRewardPool()).toBigInt() === FEE / 2n, 'the fee split 50/50');
const stored = await q.strangerNotes(windowStart, sighash);
check(stored.isSome && stored.unwrap().length === 1795, 'the 1,795-byte note is in the 24-hour buffer');
check(noteHash.toHex().length === 66, 'the note hash is in the event');

why = await refused(general(t, t.note, t.rerandomised, t.rerandomisedPowNonce));
check(why?.includes('Custom error: 7'), `a re-randomised replay is refused as a spent nullifier (${why})`);

// The pool may answer an identical resubmission in its own way, so the check
// that matters is that nothing happened twice.
await refused(general(t));
const after = await head();
while ((await head()) < after + 2) await sleep(1000);
check((await q.nextIndex()).toNumber() === 7, 'after two more blocks the tree has not grown');
check((await q.currentRoot()).toHex() === newRoot, 'the root has not moved');
check((await q.burnedFees()).toBigInt() === FEE / 2n, 'no second fee was counted');

console.log('\nAll shielded checks passed.');
await api.disconnect();
process.exit(0);
