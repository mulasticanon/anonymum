// Shields real balance into the pool and spends it with a real Groth16 proof,
// then submits the fixture Transfer, so proofs are verified inside the
// WebAssembly runtime and fees move real balance. DEV ONLY: the keys come
// from a public seed and the spent notes' secrets are in the repository.
//
//   cargo build --release --locked -p anonymum-shielded-circuit --example dev_tool   (repository root)
//   bash substrate/scripts/run-node.sh                                               (WSL)
//   cd substrate/scripts && node shielded-smoke.mjs

import { ApiPromise, WsProvider, Keyring } from '@polkadot/api';
import { compactAddLength, stringToU8a, u8aConcat, u8aToHex } from '@polkadot/util';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const TOOL = resolve(here, '../../target/release/examples', process.platform === 'win32' ? 'dev_tool.exe' : 'dev_tool');
const [CHAIN_ID, VERSION, WINDOW, FEE] = [4242, 1, 60, 1000n];
const SPEC_VERSION = 12;
/// Value of the dev genesis notes, minted into the pool account.
const GENESIS_SUPPLY = 1_013_001n;
const SHIELD_AMOUNT = 5_000_000n;
const POW_BITS = 20;

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
const tool = (args) => JSON.parse(execFileSync(TOOL, args.map(String), { encoding: 'utf8' }));

// A PalletId's account: "modl", the id, zero padding to 32 bytes.
const palletAccount = (id) => u8aToHex(u8aConcat(stringToU8a('modl'), stringToU8a(id), new Uint8Array(20)));
const POOL = palletAccount('anm/shld');
const REWARD = palletAccount('anm/rewd');
const free = async (who) => (await api.query.system.account(who)).data.free.toBigInt();
const issuance = async () => (await api.query.balances.totalIssuance()).toBigInt();
/** Balances that fees and shields move. */
const ledger = async () => ({ issuance: await issuance(), pool: await free(POOL), reward: await free(REWARD) });

/** Sign and wait for inclusion; returns the fee paid, the pallet's events and any error. */
function sendSigned(signer, tx) {
  return new Promise((resolve, reject) => {
    tx.signAndSend(signer, ({ status, events, dispatchError }) => {
      if (status.isInvalid || status.isDropped || status.isUsurped) return reject(new Error(`transaction ${status.type}`));
      if (!status.isInBlock && !status.isFinalized) return;
      const fee = events.find(({ event: e }) => e.section === 'transactionPayment' && e.method === 'TransactionFeePaid');
      resolve({
        error: dispatchError ? dispatchError.toString() : null,
        fee: fee ? fee.event.data[1].toBigInt() : 0n,
        events: events.filter(({ event: e }) => e.section === 'anonymumShielded').map(({ event }) => event),
      });
    }).catch(reject);
  });
}

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

/** The `Transacted` event of the first block after `from` that has one. */
async function shieldedEvent(from) {
  for (let tries = 0; tries < 60; tries++) {
    const top = await head();
    for (let n = from + 1; n <= top; n++) {
      const at = await api.at(await api.rpc.chain.getBlockHash(n));
      const events = await at.query.system.events();
      const found = events.find(({ event: e }) => e.section === 'anonymumShielded' && e.method === 'Transacted');
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
const genesisRoot = (await q.currentRoot()).toHex();

// ---- Real balances: the genesis reserve, shield, and a spend's fee ----
const ED = api.consts.balances.existentialDeposit.toBigInt();
check((await free(POOL)) === GENESIS_SUPPLY + ED, `the pool account holds the genesis notes' ${GENESIS_SUPPLY} units plus the existential deposit`);
check((await free(REWARD)) === ED, 'the reward account starts with the existential deposit');

// Genesis has timestamp 0, so wait for a real block time first.
while ((await nowSecs()) === 0) await sleep(1000);
const alice = new Keyring({ type: 'sr25519' }).addFromUri('//Alice');
const args = tool(['shield-note']);
const aliceBefore = await free(alice.address);
let before = await ledger();
const shielded = await sendSigned(alice, api.tx.anonymumShielded.shield(args.authority, SHIELD_AMOUNT, args.blinding));
check(!shielded.error, `shield succeeded (${shielded.error ?? 'no error'})`);
const ev = shielded.events.find((e) => e.method === 'Shielded');
check(ev !== undefined, 'shield emitted Shielded');
// Fields: who, amount, commitment, leaf_index, window_start, new_root.
const [, amount, , leafIndex, leafTime] = ev.data;
check(leafIndex.toNumber() === 4 && amount.toBigInt() === SHIELD_AMOUNT, `the note is leaf 4 and holds ${SHIELD_AMOUNT} units`);
let after = await ledger();
check((await free(alice.address)) === aliceBefore - SHIELD_AMOUNT - shielded.fee, `Alice paid ${SHIELD_AMOUNT} plus a ${shielded.fee}-unit transaction fee`);
check(after.pool === before.pool + SHIELD_AMOUNT, 'the pool account received exactly the shielded amount');
check(after.issuance === before.issuance - shielded.fee, 'issuance changed only by the transaction fee');
check((await q.nextIndex()).toNumber() === 5, 'one leaf was appended');

// Spend the shielded note with a real proof, in a window with time left.
while (WINDOW - ((await nowSecs()) % WINDOW) < 30) await sleep(2000);
const s = tool(['shield-tx', CHAIN_ID, VERSION, await nowSecs(), WINDOW, POW_BITS, SHIELD_AMOUNT, leafTime.toNumber()]);
check(s.shieldCommitment === ev.data[2].toHex(), 'the chain computed the same commitment as the circuit');
check(s.root === (await q.currentRoot()).toHex(), "the spend proves against the shield's new root");
before = await ledger();
let from = await head();
await send(general(s));
let spend = await shieldedEvent(from);
check(spend.found && !spend.failed, 'the WebAssembly runtime verified a proof spending the shielded note');
after = await ledger();
check(after.issuance === before.issuance - FEE / 2n, `total issuance fell by the ${FEE / 2n}-unit burn share`);
check(after.reward === before.reward + FEE / 2n, `the reward account gained the ${FEE / 2n}-unit reward share`);
check(after.pool === before.pool - FEE, `the pool account paid the ${FEE}-unit base fee`);
check((await q.nextIndex()).toNumber() === 8, 'the spend appended three leaves');
const startRoot = (await q.currentRoot()).toHex();

// ---- The fixture Transfer, against the genesis root (still accepted) ----
while (WINDOW - ((await nowSecs()) % WINDOW) < 30) await sleep(2000);
const started = Date.now();
const t = tool(['tx', CHAIN_ID, VERSION, await nowSecs(), WINDOW, POW_BITS]);
console.log(`\nProved a Transfer in ${Date.now() - started} ms (includes regenerating the dev keys).`);
console.log(`Solved its ${t.powBits}-bit proof of work in ${(t.powMicros / 1000).toFixed(2)} ms (nonce ${t.powNonce}).`);
check(t.root === genesisRoot && (await q.acceptedRoots(t.root)).isSome, 'proved against the genesis root, still accepted');

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

const ledgerBefore = await ledger();
const beforeTx = await head();
await send(general(t));
check(true, 'the pool accepted the general transaction, with no signer');
// Same nullifiers, different proof bytes: refused while the first is pooled
// (a tag conflict) or once it is included (a spent nullifier).
why = await refused(general(t, t.note, t.rerandomised, t.rerandomisedPowNonce));
check(why !== null, `a re-randomised copy with its own work is refused at once (${why})`);

const { found, failed } = await shieldedEvent(beforeTx);
check(found && !failed, 'the WebAssembly runtime verified the proof and accepted the transaction');
check(!JSON.stringify(found.event.data.toJSON()).includes(t.proof.slice(2)), 'the event does not carry the proof');

const [sighash, noteHash, windowStart] = found.event.data;
check((await q.nextIndex()).toNumber() === 11, 'three leaves were appended');
const newRoot = (await q.currentRoot()).toHex();
check(newRoot !== startRoot && (await q.acceptedRoots(newRoot)).isSome, 'the new root is accepted');
for (const n of t.nullifiers) check((await q.nullifiers(n)).isSome, 'nullifier recorded');
check((await q.burnedFees()).toBigInt() === FEE && (await q.nodeRewardPool()).toBigInt() === FEE, 'the counters hold two 50/50 fee splits');
const ledgerAfter = await ledger();
check(ledgerAfter.issuance === ledgerBefore.issuance - FEE / 2n && ledgerAfter.pool === ledgerBefore.pool - FEE, 'the second fee moved real balance too');
const stored = await q.strangerNotes(windowStart, sighash);
check(stored.isSome && stored.unwrap().length === 1795, 'the 1,795-byte note is in the 24-hour buffer');
check(noteHash.toHex().length === 66, 'the note hash is in the event');

why = await refused(general(t, t.note, t.rerandomised, t.rerandomisedPowNonce));
check(why?.includes('Custom error: 7'), `a re-randomised replay is refused as a spent nullifier (${why})`);

// The pool may answer an identical resubmission in its own way, so the check
// that matters is that nothing happened twice.
await refused(general(t));
const headAfter = await head();
while ((await head()) < headAfter + 2) await sleep(1000);
check((await q.nextIndex()).toNumber() === 11, 'after two more blocks the tree has not grown');
check((await q.currentRoot()).toHex() === newRoot, 'the root has not moved');
check((await q.burnedFees()).toBigInt() === FEE, 'no extra fee was counted');
check((await ledger()).issuance === ledgerAfter.issuance, 'and no extra balance moved');

console.log('\nAll shielded checks passed.');
await api.disconnect();
process.exit(0);
