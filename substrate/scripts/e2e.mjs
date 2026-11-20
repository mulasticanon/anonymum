// End-to-end run (audit F8): real wallets, a real sealed note through the
// dev chain, then a real conversation over the live Nym mixnet.
//
//   cargo build -p anonymum-nym                  (repository root)
//   bash substrate/scripts/run-node.sh            (WSL; dev node on :9944)
//   cd substrate/scripts && node e2e.mjs          (Windows or Linux)
//
// 1. Two wallets are created by `anonymum-nym wallet` (anonymum-crypto
//    `Identity`: an Ed25519 account key plus an X25519 messaging key), each
//    with a separate contact identity (spec v0.7 section 2a) and its card.
//    Their chain accounts ARE those Ed25519 keys: clients standardise on
//    Ed25519 account keys, so the address the crypto crate uses and the
//    on-chain AccountId are the same 32 bytes.
// 2. Bob publishes his real messaging key with its real binding signature.
//    (The transparent chain still requires it; notes do not use it.)
// 3. Carol creates a persisted throwaway Nym client, seals a real note to
//    the inbox key on Bob's contact card, and sends a paid request.
// 4. Bob reads the note back from chain state, opens it with his inbox key
//    alone (no sender address), and accepts.
// 5. Once the acceptance is final, Bob calls Carol's callback key at the
//    throwaway route over Nym (Noise IK); they swap long-lived routes inside
//    the encrypted session. Bob and Carol run as two separate processes that
//    share nothing but the chain and the mixnet: Bob's gets only his own
//    wallet file and the note bytes read from chain state, so the callback
//    key, route and request reference come only from the note he decrypts;
//    Carol's gets only her own files and Bob's public card.
//
// DEV ONLY: wallets are plain files in a temporary folder, deleted at the end.

import { ApiPromise, WsProvider, Keyring } from '@polkadot/api';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import { hexToU8a, u8aToHex } from '@polkadot/util';
import { execFileSync, spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
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

/** Run an anonymum-nym subcommand as its own process; resolve with its output. */
function process_(label, args) {
  return new Promise((resolvePromise) => {
    const child = spawn(BIN, args, { stdio: ['ignore', 'pipe', 'inherit'] });
    let out = '';
    child.stdout.on('data', (chunk) => {
      out += chunk;
      for (const line of chunk.toString().split(/\r?\n/)) if (line) console.log(`    [${label}] ${line}`);
    });
    child.on('close', (code) => {
      const fields = Object.fromEntries(
        out.split(/\r?\n/).filter((l) => l.includes('=')).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
      );
      resolvePromise({ code, fields });
    });
  });
}

function walletSigningSeed(file) {
  const line = readFileSync(file, 'utf8').split(/\r?\n/).find((l) => l.startsWith('signing='));
  return hexToU8a('0x' + line.slice('signing='.length).trim());
}

await cryptoWaitReady();
const api = await ApiPromise.create({ provider: new WsProvider('ws://127.0.0.1:9944'), noInitWarn: true });

/** Sign, submit, wait until finalized. Returns our events and any error. */
function send(signer, tx) {
  return new Promise((resolvePromise, reject) => {
    tx.signAndSend(signer, ({ status, events, dispatchError }) => {
      if (status.isInvalid || status.isDropped || status.isUsurped) {
        reject(new Error(`transaction ${status.type}`));
        return;
      }
      if (!status.isFinalized) return;
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
// Each person's files in their own folder; Bob's process is never given Carol's.
const bobDir = join(work, 'bob');
const carolDir = join(work, 'carol');
mkdirSync(bobDir);
mkdirSync(carolDir);
const throwawayDir = join(carolDir, 'throwaway');
try {
  console.log(`Connected to ${await api.rpc.system.chain()}, runtime ${api.runtimeVersion.specName}`);

  // ---- 1. wallets -----------------------------------------------------------
  console.log('\n1. Two wallets from anonymum-crypto; their Ed25519 keys are their chain accounts.');
  // The key binding (v2) names this chain's genesis hash and the account.
  const genesisHex = api.genesisHash.toHex().slice(2);
  const bob = rust('wallet', join(bobDir, 'bob.wallet'), '--genesis', genesisHex);
  const carol = rust('wallet', join(carolDir, 'carol.wallet'), '--genesis', genesisHex);
  const ed = new Keyring({ type: 'ed25519', ss58Format: 42 });
  const bobAccount = ed.addFromSeed(walletSigningSeed(join(bobDir, 'bob.wallet')));
  const carolAccount = ed.addFromSeed(walletSigningSeed(join(carolDir, 'carol.wallet')));
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
  console.log("\n3. Carol creates a throwaway Nym client, seals a note to the inbox key on Bob's card, and requests contact.");
  const throwaway = rust('throwaway', throwawayDir);
  check(throwaway.address.length === 192, 'throwaway Nym address created (96 bytes) and persisted; client now offline');
  const keepFile = join(carolDir, 'carol.keep');
  const { note } = rust('seal', '--card', bob.card, '--sender', join(carolDir, 'carol.wallet'),
    '--reply', throwaway.address, '--intro', INTRO, '--keep', keepFile);
  check(note.length === 2 * 667, 'sealed note is 667 bytes (admission commitment + Noise X via snow)');
  check(!note.includes(carol.address) && !note.includes(bob.address), 'no wallet address in the note');
  r = await send(carolAccount, api.tx.anonymum.requestContact(bobAccount.address, COIN, '0x' + note));
  const requested = r.events.find((e) => e.method === 'ContactRequested');
  check(r.error === null && requested, 'paid contact request on chain');
  const requestId = requested.data[0].toNumber();

  // ---- 4. Bob reads the note back from chain state and opens it -------------
  console.log('\n4. Bob reads the request from chain state, opens the note, and accepts.');
  const onChain = (await api.query.anonymum.requests(requestId)).unwrap();
  check(onChain.note.toHex() === '0x' + note, 'the note in chain state is byte-for-byte what Carol sealed');
  const opened = rust('open', '--wallet', join(bobDir, 'bob.wallet'), '--note', onChain.note.toHex().slice(2));
  check(opened.intro === INTRO, `Bob reads the intro: "${opened.intro}"`);
  check(opened.reply === throwaway.address, "and Carol's throwaway route, with no sender hint");
  r = await send(bobAccount, api.tx.anonymum.acceptContact(requestId));
  check(r.error === null && r.events.some((e) => e.method === 'ChannelOpened'), 'Bob accepted; channel open on chain (finalized)');

  // ---- 5. They talk over Nym, as two separate processes ---------------------
  console.log('\n5. Two processes: Carol answers on her throwaway route; Bob opens the note from chain state and calls back.\n');
  // Read from chain state in step 4 (accepting removes the request).
  const noteFromChain = onChain.note.toHex().slice(2);
  const carolRun = process_('carol', ['answer', '--carol', join(carolDir, 'carol.wallet'), '--keep', keepFile,
    '--dir', throwawayDir, '--card', bob.card]);
  const bobRun = process_('bob', ['callback', '--bob', join(bobDir, 'bob.wallet'), '--note', noteFromChain]);
  const [carolEnd, bobEnd] = await Promise.all([carolRun, bobRun]);
  check(carolEnd.code === 0 && carolEnd.fields.answer === 'ok', "Carol's process let in only Bob's callback and finished");
  check(bobEnd.code === 0 && bobEnd.fields.callback === 'ok', "Bob's process called back from the note alone and checked Carol's contact key");
  check(bobEnd.fields.learned === carolEnd.fields.mine && carolEnd.fields.learned === bobEnd.fields.mine,
    'they swapped long-lived routes over Nym');

  console.log('\nAll end-to-end checks passed.');
} finally {
  rmSync(work, { recursive: true, force: true });
  await api.disconnect();
}
