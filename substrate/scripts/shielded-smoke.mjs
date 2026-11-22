// Submits a real Groth16-proved shielded transaction to a local dev node, so
// the proof is verified inside the WebAssembly runtime. DEV ONLY: the keys
// come from a public seed and the spent note's secrets are in the repository.
//
//   cargo build --release --locked -p anonymum-shielded-circuit --example dev_tool   (repository root)
//   bash substrate/scripts/run-node.sh                                               (WSL)
//   cd substrate/scripts && node shielded-smoke.mjs

import { ApiPromise, WsProvider } from '@polkadot/api';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const TOOL = resolve(here, '../../target/release/examples', process.platform === 'win32' ? 'dev_tool.exe' : 'dev_tool');
const [CHAIN_ID, VERSION, WINDOW, FEE] = [4242, 1, 60, 1000n];

function check(ok, message) {
  if (!ok) {
    console.error(`  FAILED: ${message}`);
    process.exit(1);
  }
  console.log(`  ok: ${message}`);
}

const api = await ApiPromise.create({ provider: new WsProvider('ws://127.0.0.1:9944'), noInitWarn: true });
const q = api.query.anonymumShielded;
const nowSecs = async () => Math.floor(Number((await api.query.timestamp.now()).toBigInt()) / 1000);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function callOf(t, note = t.note, proof = t.proof) {
  return api.tx.anonymumShielded.submitShielded(
    t.root, t.nullifiers, t.commitments, t.admission, t.notBefore, t.notAfter, t.coin, note, proof,
  );
}

/** Resolve with the events once finalized; reject if the pool refuses it. */
function submit(tx) {
  return new Promise((resolvePromise, reject) => {
    tx.send((result) => {
      if (result.isError || result.status.isInvalid || result.status.isDropped) reject(new Error(result.status.type));
      if (result.status.isFinalized || result.status.isInBlock) resolvePromise(result);
    }).catch(reject);
  });
}

async function refused(tx) {
  try {
    await Promise.race([submit(tx), sleep(20_000).then(() => { throw new Error('timeout'); })]);
    return null;
  } catch (e) {
    return e.message;
  }
}

console.log(`Connected, spec_version ${api.runtimeVersion.specVersion}`);
check(api.runtimeVersion.specVersion.toNumber() === 8, 'runtime spec_version is 8');
check((await q.baseFee()).toBigInt() === FEE, 'dev base fee is in genesis');
check((await q.nextIndex()).toNumber() === 4, 'the tree starts with the 4 fixture leaves');
const startRoot = (await q.currentRoot()).toHex();

// Prove for a window with time left, so the block lands inside it.
while (WINDOW - ((await nowSecs()) % WINDOW) < 30) await sleep(2000);
const started = Date.now();
const t = JSON.parse(execFileSync(TOOL, ['tx', CHAIN_ID, VERSION, await nowSecs(), WINDOW].map(String), { encoding: 'utf8' }));
console.log(`\nProved a Transfer in ${Date.now() - started} ms (includes regenerating the dev keys).`);
check(t.root === startRoot, 'proved against the on-chain root');

const tampered = `0x${t.note.startsWith('0xff') ? '00' : 'ff'}${t.note.slice(4)}`;
const bad = await refused(callOf(t, tampered));
check(bad !== null, `the pool refuses a tampered stranger note (${bad})`);

const result = await submit(callOf(t));
const event = result.events.find(({ event: e }) => e.section === 'anonymumShielded' && e.method === 'Shielded');
const failed = result.events.find(({ event: e }) => e.section === 'system' && e.method === 'ExtrinsicFailed');
check(!failed && event, 'the WebAssembly runtime verified the proof and accepted the transaction');
check(result.txHash && !JSON.stringify(event.event.data.toHuman()).includes(t.proof), 'the event does not carry the proof');

const [sighash, noteHash, windowStart] = event.event.data;
check((await q.nextIndex()).toNumber() === 7, 'three leaves were appended');
const newRoot = (await q.currentRoot()).toHex();
check(newRoot !== startRoot && (await q.acceptedRoots(newRoot)).isSome, 'the new root is accepted');
for (const n of t.nullifiers) check((await q.nullifiers(n)).isSome, 'nullifier recorded');
check((await q.burnedFees()).toBigInt() === FEE / 2n && (await q.nodeRewardPool()).toBigInt() === FEE / 2n, 'the fee split 50/50');
const stored = await q.strangerNotes(windowStart, sighash);
check(stored.isSome && stored.unwrap().length === 1795, 'the 1,795-byte note is in the 24-hour buffer');
check(noteHash.toHex().length === 66, 'the note hash is in the event');

// A valid proof of the same statement, with different bytes and so a
// different transaction hash: only the nullifiers can stop it.
check(t.rerandomised !== t.proof, 'the re-randomised proof has different bytes');
const replay = await refused(callOf(t, t.note, t.rerandomised));
check(replay !== null && replay.includes('Custom error: 7'), `a re-randomised replay is refused as a spent nullifier (${replay})`);

// The pool may answer an identical resubmission with the first inclusion's
// status, so the check that matters is that nothing happened twice.
await refused(callOf(t));
const blockBefore = (await api.rpc.chain.getHeader()).number.toNumber();
while ((await api.rpc.chain.getHeader()).number.toNumber() < blockBefore + 2) await sleep(1000);
check((await q.nextIndex()).toNumber() === 7, 'after two more blocks the tree has not grown');
check((await q.currentRoot()).toHex() === newRoot, 'the root has not moved');
check((await q.burnedFees()).toBigInt() === FEE / 2n, 'no second fee was counted');

console.log('\nAll shielded checks passed.');
await api.disconnect();
process.exit(0);
