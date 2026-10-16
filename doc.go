// Package nostrmix puts Nostr relay traffic on the Nym mixnet.
//
// See the README and cmd/nostrmix. The packages are:
//
//	mixnet   SOCKS5 to nym-socks5-client, DoH over the mixnet, no clearnet fallback
//	nym      sets up and runs the official nym-socks5-client
//	nostr    NIP-01 event checks, NIP-19 npub, NIP-11, a relay client over the mixnet
//	gateway  local relay endpoint ws://127.0.0.1:7777/<relay> for unmodified clients
package nostrmix
