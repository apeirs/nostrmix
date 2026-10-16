package nostr

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Sign is a test helper: it signs e with a throwaway key (nostrmix itself
// never signs anything).
func Sign(t testing.TB, e *Event, seed byte) {
	t.Helper()
	k := sha256.Sum256([]byte{seed})
	priv, _ := btcec.PrivKeyFromBytes(k[:])
	e.PubKey = hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))
	e.ID = e.ComputeID()
	id, _ := hex.DecodeString(e.ID)
	sig, err := schnorr.Sign(priv, id)
	if err != nil {
		t.Fatal(err)
	}
	e.Sig = hex.EncodeToString(sig.Serialize())
}

func TestSignedEventChecksAndTamperingFails(t *testing.T) {
	e := &Event{CreatedAt: 1760000000, Kind: 1, Tags: [][]string{{"t", "nym"}, {"p", "ab\"c"}},
		Content: "line one\nline \"two\"\t\\ tab, emoji 🙂, ctrl \x01 and  "}
	Sign(t, e, 1)
	if err := e.Check(); err != nil {
		t.Fatal(err)
	}
	bad := *e
	bad.Content += "!"
	if bad.Check() == nil {
		t.Fatal("tampered content verified")
	}
	bad = *e
	bad.ID = bad.ComputeID() // re-hash, but the signature is for the old id
	bad.Content = "x"
	bad.ID = bad.ComputeID()
	if err := bad.Check(); err == nil || err.Error() != "signature does not verify" {
		t.Fatalf("re-hashed tampered event: %v", err)
	}
}

func TestSerializeEscaping(t *testing.T) {
	e := &Event{PubKey: "pk", CreatedAt: 1, Kind: 1, Tags: [][]string{}, Content: "a\"b\\c\nd\re\tf\bg\fh\x01é"}
	want := `[0,"pk",1,1,[],"a\"b\\c\nd\re\tf\bg\fh\u0001é"]`
	if got := string(e.Serialize()); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// testdata/real-events.jsonl holds events fetched from public relays through
// the mixnet (signed by other people's clients), so the serialisation is
// checked against real-world signers, not just against ourselves.
func TestRealWorldEventsVerify(t *testing.T) {
	f, err := os.Open("testdata/real-events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, ReadLimit)
	n := 0
	for sc.Scan() {
		e, err := ParseEvent(sc.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Check(); err != nil {
			t.Fatalf("event %s (kind %d): %v", e.ID, e.Kind, err)
		}
		n++
	}
	if n < 5 {
		t.Fatalf("only %d real events", n)
	}
}

func TestNpub(t *testing.T) {
	// NIP-19 example.
	const npub = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"
	const hx = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
	got, err := PubKeyHex(npub)
	if err != nil || got != hx {
		t.Fatalf("%s %v", got, err)
	}
	b, _ := hex.DecodeString(hx)
	if enc := Bech32Encode("npub", b); enc != npub {
		t.Fatal(enc)
	}
	if _, err := PubKeyHex(npub[:len(npub)-1] + "q"); err == nil {
		t.Fatal("bad checksum accepted")
	}
	if got, _ := PubKeyHex("nostr:" + npub); got != hx {
		t.Fatal("nostr: prefix")
	}
	if _, err := PubKeyHex("nsec1xyz"); err == nil {
		t.Fatal("nsec accepted as a pubkey")
	}
}

func TestRelayURL(t *testing.T) {
	for in, want := range map[string]string{
		"nos.lol":                 "wss://nos.lol/",
		"wss://relay.damus.io":    "wss://relay.damus.io/",
		"https://x.org:8443/in?a": "wss://x.org:8443/in?a",
	} {
		u, err := RelayURL(in, false)
		if err != nil || u.String() != want {
			t.Fatalf("%s -> %v %v", in, u, err)
		}
	}
	if _, err := RelayURL("ws://nos.lol", false); err == nil {
		t.Fatal("plain ws accepted")
	}
	if u, err := RelayURL("ws://nos.lol", true); err != nil || Port(u) != 80 {
		t.Fatal("plain ws with allowPlain")
	}
	if _, err := RelayURL("wss://user@nos.lol", false); err == nil {
		t.Fatal("userinfo accepted")
	}
}
