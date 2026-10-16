# nostrmix: Nostr relays through the Nym mixnet

`nostrmix` hides your IP address from the Nostr relays you read from and
publish to. It has two parts:

- **A local relay gateway.** `nostrmix serve` listens on `127.0.0.1:7777`. In
  your Nostr client you add relays as `ws://127.0.0.1:7777/<relay host>`, for
  example `ws://127.0.0.1:7777/nos.lol`. nostrmix opens `wss://nos.lol`
  **through the Nym mixnet** and copies WebSocket messages both ways without
  changing them. Any client that lets you type a relay URL can use it, with no
  code changes. That includes clients that have no proxy setting at all.
- **A CLI that speaks Nostr over the mixnet directly.** `req` fetches events
  from several relays and checks every id and signature. `publish` sends an
  event you signed elsewhere to many relays at once. `info` fetches the NIP-11
  document, `probe` shows which relays accept Nym exit traffic and how fast,
  and `ip` shows which address the relays see.

It is a single Go binary. It drives Nym's official `nym-socks5-client` and
does not reimplement any mixnet cryptography: Sphinx packets, cover traffic,
Poisson delays and gateway handling all come from Nym's code. nostrmix never
sees or stores a private key.

By apeir (https://apeir.dk/online/). MIT licence.

---

## The problem

Nostr hides nothing at the network layer. Every client keeps WebSocket
connections open to 5 to 20 relays, all from your IP address, all day. Each
relay operator, and anyone who can watch or subpoena a relay, learns:

- **which IP publishes as which pubkey.** That breaks pseudonymity for anyone
  who posts under a name that isn't their legal one, the use Nostr is often
  recommended for.
- **which IP follows whom.** Subscriptions name the authors and threads you
  read, and they are tied to the connection.
- **when you are online, and for how long.**

Relays share this data with each other just by existing: the same IP shows up
on all of them at once, so one pubkey's IP on relay A links to its activity on
relay B. Signing and encryption can't fix this, because it is metadata about
the connection.

Tor helps when the client supports a SOCKS proxy, and some mobile clients do
(Amethyst with Orbot). Most desktop clients and **every web client** (Coracle,
Snort, noStrudel, Iris, Primal web) cannot use a proxy at all. nostrmix gives
all of them a mixnet path. Unlike Tor, the Nym mixnet also mixes and delays
packets and adds cover traffic, which is meant to defeat the timing
correlation an observer of a long-lived, chatty WebSocket can otherwise do.

## Design

```
 Nostr client (web, desktop, CLI): ws://127.0.0.1:7777/nos.lol
   │  loopback only (Host header checked against DNS rebinding)
   ▼
 nostrmix serve ── WebSocket in, WebSocket out, messages copied as-is
   │  TLS to nos.lol (verified against system roots, SNI nos.lol)
   ▼  ...inside a SOCKS5 stream
 nym-socks5-client 127.0.0.1:1080 ── Sphinx packets, cover traffic, reply SURBs
   ▼
 entry gateway → 3 mix layers → exit gateway (network requester, Nym exit policy)
   ▼  TCP 443
 public relay (nos.lol) ── sees the exit gateway's IP, not yours
```

- **End-to-end TLS.** The exit gateway relays ciphertext only. The relay's
  certificate is verified for the real hostname. Plain `ws://` upstreams are
  refused unless you pass `--allow-plain`.
- **No clearnet fallback.** If `nym-socks5-client` is not running, the gateway
  answers every connection with HTTP 502 and the CLI refuses to connect. It
  never goes direct. The tests check this against a relay that counts
  connections.
- **Upstream first.** The gateway opens the relay connection through the
  mixnet *before* it accepts the client's WebSocket. Your client shows the
  relay as connected only when the mixnet path really works. A failure
  becomes an ordinary connection error that the client retries with its own
  backoff.
- **No local DNS.** By default (`--dns doh`) relay names are resolved with
  DNS-over-HTTPS *sent through the mixnet* (Cloudflare 1.1.1.1, then Google
  8.8.8.8, reached by IP literal), then connected by IPv4. Some exits have
  broken IPv6 routes and stall on AAAA records. `--dns exit` hands the name
  to the exit instead. Either way, your local resolver never sees which
  relays you use.
- **Nothing identifying goes upstream.** The client's `Origin`, cookies and
  `User-Agent` are not forwarded. The relay gets one fixed, common
  `User-Agent` and no `Origin`. The tests send a fingerprintable client and
  check what the relay received.
- **Keepalive.** Mixnet streams that go quiet can be dropped along the way.
  The gateway pings each relay every 30 s, so an idle subscription stays open:
  a live subscription was held for 4 minutes in the test below.
- **Compression.** The CLI and gateway ask relays for permessage-deflate.
  Nostr JSON compresses well, so fewer Sphinx packets cross the mixnet. The
  loopback side is uncompressed.
- **Loopback only.** `serve` refuses a non-loopback `--listen` unless you pass
  `--public`, and it checks the `Host` header so that a web page can't reach
  the gateway through DNS rebinding.
- **Web clients.** Any origin may connect by default, because web clients are
  a main use case. `--origin coracle.social,snort.social` restricts it, and
  `--only nos.lol,relay.primal.net` limits which relays can be reached.
  Upstream ports are limited to 443 (`--allow-port` to change).
- **NIP-11 too.** A GET to `http://127.0.0.1:7777/<relay>` with
  `Accept: application/nostr+json` returns the relay's information document,
  fetched through the mixnet, with the CORS header NIP-11 asks for. Clients
  that read relay limits keep working.

## Install

```sh
go install github.com/apeirs/nostrmix/cmd/nostrmix@latest   # Go 1.26+
```

Download `nym-socks5-client` from the Nym releases
(https://github.com/nymtech/nym/releases, the `nym-binaries-*` assets). Check
its sha256 against the release's `hashes.json`, `chmod +x` it, and put it on
your `PATH` or set `NOSTRMIX_NYM_SOCKS5=/path/to/nym-socks5-client`. I tested
with the binary built 2026-10-01 (sha256 `24193bfa…534f`).

## Use

```sh
nostrmix nym setup          # init on a random active exit gateway, start, wait until ready
nostrmix ip                 # check: relays see a Nym exit gateway's IP, not yours
nostrmix serve              # gateway on ws://127.0.0.1:7777
```

Then in your Nostr client, replace each relay `wss://HOST` with
`ws://127.0.0.1:7777/HOST`:

```
wss://nos.lol             ->  ws://127.0.0.1:7777/nos.lol
wss://relay.primal.net    ->  ws://127.0.0.1:7777/relay.primal.net
wss://nostr.wine          ->  ws://127.0.0.1:7777/nostr.wine
```

`ws://127.0.0.1:7777/wss://nos.lol` works too. Paths and query strings are
passed on (`ws://127.0.0.1:7777/relay.example.com/inbox`). With
`--default nos.lol`, plain `ws://127.0.0.1:7777` goes to that relay.
`http://127.0.0.1:7777/` shows a status page and `/stats` gives counters as
JSON.

If your client *does* support a SOCKS5 proxy, you can point it at
`nym-socks5-client` directly. nostrmix still adds DNS through the mixnet, the
no-fallback guarantee and header stripping, but the gateway exists mainly for
the clients that can't do that.

### CLI

```sh
# fetch events (JSON lines on stdout, summary on stderr); ids + signatures checked
nostrmix req nos.lol relay.primal.net --kinds 1 --tag t=nym --limit 20
nostrmix req nos.lol --authors npub1... --since 7d
nostrmix req nos.lol --filter '{"kinds":[0],"authors":["<hex>"]}'

# publish an event signed by your own client / nak / a bunker
nak event --sec ... -c 'hello' | nostrmix publish nos.lol relay.primal.net offchain.pub -

nostrmix info nostr.wine        # NIP-11
nostrmix probe                  # which popular relays work over the mixnet right now
nostrmix nym exits              # active exit gateways that enforce the exit policy
nostrmix nym setup --force      # new identity, new random exit gateway
```

`publish` checks the event's id and BIP-340 signature before sending and
refuses a broken event (relays would drop it anyway). Each relay gets its own
mixnet stream and its own `OK` line.

## Live test (2026-10-16)

Everything below ran over the real Nym mainnet mixnet through
`nym-socks5-client` (exit gateway: node 2002, picked at random from 98 active
exit gateways). Full logs are in `examples/`.

**Which IP do relays see?**
```
https://api.ipify.org sees this request coming from 79.141.169.35 (6.15s over the mixnet)
= Nym node 2002 (HK, exit gateway: true) in the nym-api node list
```

**`nostrmix probe`** (connect, then `REQ {"kinds":[1],"limit":3}` with
signature checks):
```
RELAY               OK     CONNECT  EOSE  EVENTS
nos.lol             true   10.5s    2.0s  3
relay.primal.net    true   8.5s     1.2s  3
nostr.wine          true   9.4s     3.1s  3
relay.snort.social  true   9.7s     1.8s  3
offchain.pub        true   8.0s     1.1s  3
nostr.mom           true   7.9s     1.2s  3
relay.damus.io      false  7.4s     -     0   connected, but no answer to REQ
relay.nostr.band    false  -        -     0   TLS handshake timeout
```
relay.damus.io and relay.nostr.band failed **on clearnet too** at the time
(damus returned HTTP 503 or stayed silent, nostr.band timed out), so these are
relay outages, not mixnet problems.

**An unmodified client through the gateway.** nostr-tools 2.25.2
`SimplePool`, which knows nothing about Nym, pointed at four
`ws://127.0.0.1:7777/...` relays:
```
querySync via ws://127.0.0.1:7777/nos.lol ws://127.0.0.1:7777/relay.primal.net ws://127.0.0.1:7777/nostr.mom ws://127.0.0.1:7777/offchain.pub
 -> 19 events, 19 verified by nostr-tools, 7.2s
 publish ...: fulfilled (4 of 4 relays OK), 1.2s
```
The published event was ephemeral (kind 20001, which relays forward but don't
store) and signed with a throwaway key.

**A long-lived subscription** (plain python-websockets client, `REQ` for new
kind-1 notes on nos.lol): held for 245 s, 72 new notes streamed in real time,
first one after 8.7 s.

**CLI publish** of a signed ephemeral event to 5 relays: accepted by 5 of 5
in 8 to 15 s each. A tampered copy was refused locally with
`id mismatch ... relays would reject it`.

Rough numbers: opening a relay connection takes 2 to 15 s through the mixnet.
After that a REQ to EOSE round trip is 1 to 3 s, and live events arrive with
about 1 to 2 s of extra delay.

## Tests

```sh
go test ./...
```

Offline tests use a fake mixnet: a SOCKS5 proxy that records every CONNECT, a
DoH resolver and a TLS Nostr relay, all on loopback with a throwaway CA. They
check that:

- an unmodified WebSocket client gets EVENT/EVENT/EOSE and OK through the
  gateway, and the proxy saw exactly two CONNECTs (DoH at 1.1.1.1, then the
  relay's IPv4) and nothing by name;
- the relay saw no `Origin`, `Cookie` or client `User-Agent`;
- with the proxy down, the gateway answers 502 and the relay is never
  contacted;
- the DNS-rebinding guard, `--only`, port and plain-`ws` rules refuse requests
  before anything reaches the proxy;
- NIP-11 works through the gateway with CORS, and relay close codes reach the
  client;
- event ids and signatures verify for 12 real events fetched from public
  relays (JSON in content, CJK, Arabic, emoji, newlines), tampering is caught,
  and NIP-19 npub decoding matches the spec's example.

## Limits (read these)

- **It hides your IP, not your identity.** Everything you publish is signed by
  your pubkey. Relays still see what you subscribe to and when, just not from
  which IP. If you already used a pubkey without the mixnet, relays may have
  logged your IP for it.
- **Your client still fetches other things directly.** Avatars, images,
  videos, link previews, NIP-05 checks and zap (LNURL) requests usually go
  straight from your client to many web servers, outside nostrmix. Turn off
  automatic media loading in your client, or the image hosts learn your IP
  and what you read. This is the biggest gap. A mixnet HTTP proxy for media
  is on the roadmap.
- **One exit for everything.** All relay connections leave through the same
  exit gateway, so relays (or someone who can watch several of them) can see
  that several connections came from the same exit at the same time. Other
  Nym users share that exit, which helps. `nostrmix nym setup --force` picks a
  new random exit.
- **The exit gateway sees the relay's hostname** (TLS SNI) and the size and
  timing of the traffic, but not the content.
- **Some relays don't work through Nym exits.** Some block datacenter or VPN
  IPs, and some are down. Run `nostrmix probe` with your relay list.
- **Latency.** Connecting takes seconds, not milliseconds. Clients with short
  connect timeouts may mark a relay as down before the mixnet handshake
  finishes. Most clients retry.
- **Browsers not tested yet.** Chrome and Firefox treat `127.0.0.1` as a
  secure context, so `https://` web clients can open `ws://127.0.0.1`. I
  tested with Node's built-in WebSocket (the same API browsers use) and
  python-websockets, not inside a browser yet. Safari has historically been
  stricter.
- **Same machine only.** A phone can't use a gateway on your desktop unless
  you pass `--public` and protect the port yourself.
- Version 0.1, not audited.

## Prior art

[notrustverify/nostr-nym](https://github.com/notrustverify/nostr-nym) (2023)
runs a Nostr relay as a Nym service provider. It needs a mixnet-aware client
and only reaches relays that run its service. nostrmix goes the other way: it
uses Nym's exit gateways (network requesters with the exit policy), so it
reaches **any** public relay with **unmodified** clients.

## Roadmap

- A mixnet HTTP proxy for media, NIP-05 and LNURL, so a client's other traffic
  can go through the mixnet too.
- Exit isolation: an option to give each relay its own `nym-socks5-client`
  identity and exit, so relays can't link connections by exit IP.
- A small relay-list rewriter: turn a NIP-65 relay list into gateway URLs for
  clients that import relay lists.
- Packaging (static release binaries, a systemd user unit).

## Layout

```
cmd/nostrmix   CLI: nym, serve, req, publish, info, probe, ip
gateway        local relay endpoint (WebSocket in, mixnet WebSocket out)
nostr          NIP-01 ids + BIP-340 checks, NIP-19 npub, NIP-11, relay client
mixnet         SOCKS5 client, DoH over the mixnet, no fallback
nym            sets up / runs the official nym-socks5-client
internal/fakes fake SOCKS5 proxy, DoH resolver and TLS relay for tests
```
