// End-to-end run (audit F8): real wallets, a real sealed note through the
// dev chain, then a real conversation over the live Nym mixnet.
//
//   cargo build -p anonymum-nym                  (repository root)
//   bash substrate/scripts/run-node.sh            (WSL; dev node on :9944)
//   cd substrate/scripts && node e2e.mjs          (Windows or Linux)
//
// 1. Two wallets are created by `anonymum-nym wallet` (anonymum-crypto
//    `Identity`: an Ed25519 account key plus an X25519 messaging key).
//    Their chain accounts ARE those Ed25519 keys: clients standardise on
//    Ed25519 account keys, so the address the crypto crate uses and the
//    on-chain AccountId are the same 32 bytes.
// 2. Bob publishes his real messaging key with its real binding signature.
// 3. Carol creates a persisted throwaway Nym client, reads Bob's key from
//    chain state, seals a real note to it, and sends a paid request.
// 4. Bob reads the note back from chain state, opens it, and accepts.
// 5. Bob calls Carol at the throwaway address over Nym; they swap
//    long-lived addresses inside the encrypted session.
//
// DEV ONLY: wallets are plain files in a temporary folder, deleted at the end.

import { ApiPromise, WsProvider, Keyring } from '@polkadot/api';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import { hexToU8a, u8aToHex } from '@polkadot/util';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const COIN = 1_000_000n;
const here = dirname(fileURLToPath(import.meta.url));
const BIN = resolve(here, '../../target/debug', process.platform === 'win32' ? 'anonymum-nym.exe' : 'anonymum-nym');
const INTRO = "Hello Bob, it's Carol from the climbing club. Can we talk about Saturday?";

function check(ok, message) {
  if (!ok) {
    console.error(`  FAILED: ${message}`);
    process.exit(1);
  }
  console.log(`  ok: ${message}`);
}

/** Run an anonymum-nym subcommand and parse its `key=value` lines. */
function rust(...args) {
  const out = execFileSync(BIN, args, { encoding: 'utf8' });
  return Object.fromEntries(
    out.split(/\r?\n/).filter((l) => l.includes('=')).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
  );
}

function walletSigningSeed(file) {
  const line = readFileSync(file, 'utf8').split(/\r?\n/).find((l) => l.startsWith('signing='));
  return hexToU8a('0x' + line.slice('signing='.length).trim());
}

await cryptoWaitReady();
const api = await ApiPromise.create({ provider: new WsProvider('ws://127.0.0.1:9944'), noInitWarn: true });

/** Sign, submit, wait until in a block (or finalized). Returns our events and any error. */
function send(signer, tx) {
  return new Promise((resolvePromise, reject) => {
    tx.signAndSend(signer, ({ status, events, dispatchError }) => {
      if (status.isInvalid || status.isDropped || status.isUsurped) {
        reject(new Error(`transaction ${status.type}`));
        return;
      }
      if (!status.isInBlock && !status.isFinalized) return;
      let error = null;
      if (dispatchError) {
        const meta = dispatchError.isModule ? api.registry.findMetaError(dispatchError.asModule) : null;
        error = meta ? `${meta.section}.${meta.name}` : dispatchError.toString();
      }
      resolvePromise({ error, events: events.map((e) => e.event).filter((e) => e.section === 'anonymum') });
    }).catch(reject);
  });
}

const work = mkdtempSync(join(tmpdir(), 'anonymum-e2e-'));
const throwawayDir = join(work, 'carol-throwaway');
try {
  console.log(`Connected to ${await api.rpc.system.chain()}, runtime ${api.runtimeVersion.specName}`);

  // ---- 1. wallets -----------------------------------------------------------
  console.log('\n1. Two wallets from anonymum-crypto; their Ed25519 keys are their chain accounts.');
  const bob = rust('wallet', join(work, 'bob.wallet'));
  const carol = rust('wallet', join(work, 'carol.wallet'));
  const ed = new Keyring({ type: 'ed25519', ss58Format: 42 });
  const bobAccount = ed.addFromSeed(walletSigningSeed(join(work, 'bob.wallet')));
  const carolAccount = ed.addFromSeed(walletSigningSeed(join(work, 'carol.wallet')));
  check(u8aToHex(bobAccount.publicKey) === '0x' + bob.address, "Bob's chain account is his wallet's Ed25519 address");
  check(u8aToHex(carolAccount.publicKey) === '0x' + carol.address, "Carol's chain account is her wallet's Ed25519 address");

  const faucet = new Keyring({ type: 'sr25519' }).addFromUri('//Alice'); // DEV ONLY
  for (const who of [bobAccount, carolAccount]) {
    const r = await send(faucet, api.tx.balances.transferKeepAlive(who.address, 10n * COIN));
    check(r.error === null, `funded ${who.address.slice(0, 8)}… with 10 coins from the dev faucet`);
  }

  // ---- 2. Bob publishes his real messaging key ------------------------------
  console.log('\n2. Bob publishes his X25519 messaging key with his Ed25519 binding signature.');
  let r = await send(bobAccount, api.tx.anonymum.publishMessagingKey('0x' + bob.msgkey, { Ed25519: '0x' + bob.binding }));
  check(r.error === null && r.events.some((e) => e.method === 'MessagingKeyPublished'), 'the chain verified the binding and stored the key');
  const stored = (await api.query.anonymum.messagingKeys(bobAccount.address)).unwrap();
  check(stored.key.toHex() === '0x' + bob.msgkey, 'the key in chain state is the wallet\'s real key');

  // ---- 3. Carol seals a real note and pays to reach Bob ---------------------
  console.log('\n3. Carol creates a throwaway Nym client, seals a note to the key from chain state, and requests contact.');
  const throwaway = rust('throwaway', throwawayDir);
  check(throwaway.address.length === 192, 'throwaway Nym address created (96 bytes) and persisted; client now offline');
  const keyFromChain = (await api.query.anonymum.messagingKeys(bobAccount.address)).unwrap().key.toHex().slice(2);
  const { note } = rust('seal', '--key', keyFromChain, '--from', carol.address, '--to', bob.address,
    '--reply', throwaway.address, '--intro', INTRO);
  check(note.length === 2 * 427, 'sealed note is 427 bytes (Noise N via snow)');
  r = await send(carolAccount, api.tx.anonymum.requestContact(bobAccount.address, COIN, '0x' + note));
  const requested = r.events.find((e) => e.method === 'ContactRequested');
  check(r.error === null && requested, 'paid contact request on chain');
  const requestId = requested.data[0].toNumber();

  // ---- 4. Bob reads the note back from chain state and opens it -------------
  console.log('\n4. Bob reads the request from chain state, opens the note, and accepts.');
  const onChain = (await api.query.anonymum.requests(requestId)).unwrap();
  check(onChain.note.toHex() === '0x' + note, 'the note in chain state is byte-for-byte what Carol sealed');
  const opened = rust('open', '--wallet', join(work, 'bob.wallet'), '--from', onChain.from.toHex().slice(2), '--note', onChain.note.toHex().slice(2));
  check(opened.intro === INTRO, `Bob reads the intro: "${opened.intro}"`);
  check(opened.reply === throwaway.address, "and Carol's throwaway address");
  r = await send(bobAccount, api.tx.anonymum.acceptContact(requestId));
  check(r.error === null && r.events.some((e) => e.method === 'ChannelOpened'), 'Bob accepted; channel open on chain');

  // ---- 5. They talk over Nym --------------------------------------------------
  console.log('\n5. Bob calls Carol over the live Nym mixnet at the address from the note.\n');
  const talk = spawnSync(BIN, ['talk', '--bob', join(work, 'bob.wallet'), '--carol', join(work, 'carol.wallet'),
    '--dir', throwawayDir, '--reply', opened.reply], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
  process.stdout.write(talk.stdout.split(/\r?\n/).map((l) => '    ' + l).join('\n') + '\n');
  check(talk.status === 0 && talk.stdout.includes('talk=ok'), 'Bob and Carol completed the handshake and swapped long-lived addresses over Nym');

  console.log('\nAll end-to-end checks passed.');
} finally {
  rmSync(work, { recursive: true, force: true });
  await api.disconnect();
}
