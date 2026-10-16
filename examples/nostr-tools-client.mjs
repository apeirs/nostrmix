// Unmodified nostr-tools client pointed at the nostrmix gateway.
const base = process.argv[2]; // e.g. /tmp/ntools/node_modules/nostr-tools/lib/esm
const gw = process.argv[3];   // e.g. ws://127.0.0.1:7777
const { SimplePool } = await import(base + '/pool.js');
const { generateSecretKey, finalizeEvent, verifyEvent } = await import(base + '/pure.js');
const relays = ['nos.lol', 'relay.primal.net', 'nostr.mom', 'offchain.pub'].map(r => `${gw}/${r}`);
const pool = new SimplePool();
let t0 = Date.now();
const evs = await pool.querySync(relays, { kinds: [1], limit: 5 }, { maxWait: 90000 });
const ok = evs.filter(e => verifyEvent(e)).length;
console.log(`querySync via ${relays.join(' ')}\n -> ${evs.length} events, ${ok} verified by nostr-tools, ${((Date.now()-t0)/1000).toFixed(1)}s`);
// Ephemeral event (kind 20000-29999: relays forward but do not store it), throwaway key.
const ev = finalizeEvent({ kind: 20001, created_at: Math.floor(Date.now()/1000), tags: [], content: 'nostrmix gateway test (ephemeral)' }, generateSecretKey());
t0 = Date.now();
const res = await Promise.allSettled(pool.publish(relays, ev));
res.forEach((r, i) => console.log(` publish ${relays[i]}: ${r.status} ${r.status === 'fulfilled' ? JSON.stringify(r.value) : r.reason}`));
console.log(` publish took ${((Date.now()-t0)/1000).toFixed(1)}s`);
pool.close(relays);
process.exit(0);
