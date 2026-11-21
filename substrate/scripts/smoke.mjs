// Sends real signed transactions to a local Anonymum dev node and checks
// balances and events after each one. Exits non-zero on the first mismatch.
//
//   cd substrate/scripts && npm install && node smoke.mjs
//
// Needs a fresh dev node on ws://127.0.0.1:9944 (see README, "Local node").
// Uses the well-known dev accounts (//Alice, //Bob, ...). Never use these
// keys for anything real.

import { ApiPromise, WsProvider, Keyring } from '@polkadot/api';
import { blake2AsU8a, cryptoWaitReady, decodeAddress, ed25519PairFromSeed, ed25519Sign } from '@polkadot/util-crypto';
import { stringToU8a, u8aConcat, u8aToHex } from '@polkadot/util';

const COIN = 1_000_000n;
const INVITE_FEE = COIN / 100n;
const COLD_FEE = COIN / 2n;
const DECLINE_FEE = COIN / 100n;
// Hex, because Polkadot.js reads a raw Uint8Array as already length-prefixed.
const NOTE = u8aToHex(new Uint8Array(1795).fill(0xab));

await cryptoWaitReady();
const api = await ApiPromise.create({ provider: new WsProvider('ws://127.0.0.1:9944'), noInitWarn: true });
const keyring = new Keyring({ type: 'sr25519' });
const [alice, bob, charlie, dave] = ['//Alice', '//Bob', '//Charlie', '//Dave'].map((uri) => keyring.addFromUri(uri));
const names = new Map([[alice.address, 'alice'], [bob.address, 'bob'], [charlie.address, 'charlie'], [dave.address, 'dave']]);

let feesPaid = 0n;

function check(ok, message) {
  if (!ok) {
    console.error(`  FAILED: ${message}`);
    process.exit(1);
  }
  console.log(`  ok: ${message}`);
}

async function account(who) {
  const { data } = await api.query.system.account(who.address);
  return { free: data.free.toBigInt(), held: data.reserved.toBigInt() };
}

/** Sign, submit, wait for inclusion. Returns our events, the error (if any) and the fee. */
function send(signer, tx) {
  return new Promise((resolve, reject) => {
    tx.signAndSend(signer, ({ status, events, dispatchError }) => {
      // The dev node finalizes each block as it seals it, so a transaction
      // may go straight from Ready to Finalized without an InBlock status.
      if (status.isInvalid || status.isDropped || status.isUsurped) {
        reject(new Error(`transaction ${status.type}`));
        return;
      }
      if (!status.isInBlock && !status.isFinalized) return;
      let error = null;
      if (dispatchError) {
        if (dispatchError.isModule) {
          const meta = api.registry.findMetaError(dispatchError.asModule);
          error = `${meta.section}.${meta.name}`;
        } else {
          error = dispatchError.toString();
        }
      }
      let fee = 0n;
      const ours = [];
      for (const { event } of events) {
        if (event.section === 'transactionPayment' && event.method === 'TransactionFeePaid') {
          fee = event.data[1].toBigInt();
        }
        if (event.section === 'anonymum') ours.push(event);
      }
      feesPaid += fee;
      const block = (status.isInBlock ? status.asInBlock : status.asFinalized).toHex().slice(0, 10);
      resolve({ error, fee, events: ours, block });
    }).catch(reject);
  });
}

function eventNames(result) {
  return result.events.map((e) => e.method);
}

const startIssuance = (await api.query.balances.totalIssuance()).toBigInt();
const header = await api.rpc.chain.getHeader();
console.log(`Connected to ${await api.rpc.system.chain()} at block #${header.number}, runtime ${api.runtimeVersion.specName}`);

// ---- B: messaging keys ------------------------------------------------------
console.log('\n1. Bob publishes his messaging key (signed by his account key).');
const bobKey = blake2AsU8a('bob/messaging');
// v2 messages carry the chain's genesis hash (and the binding the account).
const genesis = api.genesisHash.toU8a();
const binding = { Sr25519: bob.sign(u8aConcat(stringToU8a('anonymum/msgkey-binding/v2'), genesis, decodeAddress(bob.address), bobKey)) };
let r = await send(bob, api.tx.anonymum.publishMessagingKey(bobKey, binding));
check(r.error === null && eventNames(r).includes('MessagingKeyPublished'), `published in block ${r.block}`);
r = await send(charlie, api.tx.anonymum.publishMessagingKey(bobKey, binding));
check(r.error === 'anonymum.BadKeyBinding', `Charlie cannot publish Bob's key as his own (${r.error})`);

// ---- invites ----------------------------------------------------------------
console.log('\n2. Bob registers an invite; Alice opens a channel with it.');
const invite = ed25519PairFromSeed(blake2AsU8a('anonymum-smoke/invite-1'));
r = await send(bob, api.tx.anonymum.registerInvite(invite.publicKey, null));
check(r.error === null, 'invite registered');
let before = await account(alice);
const proof = ed25519Sign(
  u8aConcat(stringToU8a('anonymum/invite/v2'), genesis, decodeAddress(alice.address), decodeAddress(bob.address)),
  invite,
);
r = await send(alice, api.tx.anonymum.openWithInvite(bob.address, invite.publicKey, proof));
check(r.error === null && eventNames(r).includes('ChannelOpened'), 'channel opened via invite');
let after = await account(alice);
check(before.free - after.free === INVITE_FEE + r.fee, `Alice paid the invite fee (0.01) plus the transaction fee (${r.fee} units)`);
const aliceChannel = r.events.find((e) => e.method === 'ChannelOpened').data[0].toNumber();

// ---- paid request, accept ---------------------------------------------------
console.log('\n3. Charlie, a stranger, pays to reach Bob with a sealed note; Bob accepts.');
before = await account(charlie);
r = await send(charlie, api.tx.anonymum.requestContact(bob.address, COIN, NOTE));
check(r.error === null && eventNames(r).includes('ContactRequested'), 'request on chain with its 1,795-byte note');
after = await account(charlie);
check(before.free - after.free === COLD_FEE + COIN + r.fee, 'Charlie paid 0.5 network fee + 1.0 price + transaction fee');
check(after.held - before.held === COIN, 'the 1.0 price is held in escrow');
const charlieRequest = r.events.find((e) => e.method === 'ContactRequested').data[0].toNumber();
const bobBefore = await account(bob);
r = await send(bob, api.tx.anonymum.acceptContact(charlieRequest));
check(r.error === null && eventNames(r).includes('ChannelOpened'), 'Bob accepted; channel open');
const bobAfter = await account(bob);
check(bobAfter.free - bobBefore.free === COIN - r.fee, 'Bob received the escrowed 1.0 (minus his transaction fee)');
check((await account(charlie)).held === 0n, "Charlie's escrow is released");

// ---- decline fee ------------------------------------------------------------
console.log('\n4. Dave requests Bob; Bob declines.');
r = await send(dave, api.tx.anonymum.requestContact(bob.address, COIN, NOTE));
check(r.error === null, 'Dave requested');
const daveRequest = r.events.find((e) => e.method === 'ContactRequested').data[0].toNumber();
r = await send(bob, api.tx.anonymum.cancelRequest(daveRequest));
const refunded = r.events.find((e) => e.method === 'RequestRefunded');
check(
  refunded && refunded.data[2].toBigInt() === COIN - DECLINE_FEE && refunded.data[3].toBigInt() === DECLINE_FEE,
  'Dave got 0.99 back; 0.01 decline fee burned',
);

// ---- A: blocks --------------------------------------------------------------
console.log('\n5. Bob blocks Dave; Dave tries again.');
r = await send(bob, api.tx.anonymum.block(dave.address));
check(r.error === null && eventNames(r).includes('Blocked'), 'Dave is blocked');
before = await account(dave);
r = await send(dave, api.tx.anonymum.requestContact(bob.address, COIN, NOTE));
after = await account(dave);
check(r.error === 'anonymum.Blocked', `Dave's request fails (${r.error})`);
check(before.free - after.free === r.fee && after.held === before.held,
  `no Anonymum fee or escrow taken; only the chain's transaction fee (${r.fee} units)`);

console.log('\n6. Bob closes his channel with Alice; Alice is blocked from paying to reach him.');
r = await send(bob, api.tx.anonymum.closeChannel(aliceChannel));
check(r.error === null && eventNames(r).join(',') === 'ChannelClosed,Blocked', 'closed, and Alice blocked');
r = await send(alice, api.tx.anonymum.requestContact(bob.address, COIN, NOTE));
check(r.error === 'anonymum.Blocked', `Alice's paid request fails (${r.error})`);

// ---- conservation -----------------------------------------------------------
console.log('\n7. Every coin accounted for.');
const endIssuance = (await api.query.balances.totalIssuance()).toBigInt();
const palletBurns = INVITE_FEE / 2n + 2n * (COLD_FEE / 2n) + DECLINE_FEE;
check(startIssuance - endIssuance === palletBurns + feesPaid,
  `issuance fell by exactly the pallet burns (${palletBurns}) plus transaction fees (${feesPaid}), which this runtime burns`);

console.log(`\nAll checks passed at block #${(await api.rpc.chain.getHeader()).number}.`);
await api.disconnect();
