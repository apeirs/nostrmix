// Package nostr has the small part of Nostr (NIP-01, NIP-11, NIP-19) that
// nostrmix needs: event ids and signature checks, filters, npub decoding and a
// relay client whose WebSocket runs through the Nym mixnet.
//
// nostrmix never holds a private key. Events are signed elsewhere (your
// client, nak, a signer) and only checked and relayed here.
package nostr

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Event is a NIP-01 event.
type Event struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

// Serialize returns the NIP-01 commitment [0,pubkey,created_at,kind,tags,content]
// with the escaping rules of the spec (no HTML escaping, UTF-8 kept as is).
func (e *Event) Serialize() []byte {
	var b bytes.Buffer
	b.WriteString(`[0,"`)
	b.WriteString(e.PubKey)
	b.WriteString(`",`)
	fmt.Fprintf(&b, "%d,%d,", e.CreatedAt, e.Kind)
	b.WriteByte('[')
	for i, tag := range e.Tags {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('[')
		for j, s := range tag {
			if j > 0 {
				b.WriteByte(',')
			}
			writeString(&b, s)
		}
		b.WriteByte(']')
	}
	b.WriteString("],")
	writeString(&b, e.Content)
	b.WriteByte(']')
	return b.Bytes()
}

// writeString escapes exactly the characters NIP-01 lists: \n \" \\ \r \t \b \f,
// other control characters as \u00XX, everything else verbatim.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if c < 0x20 {
				fmt.Fprintf(b, `\u%04x`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
}

// ComputeID is the hex sha256 of Serialize().
func (e *Event) ComputeID() string {
	h := sha256.Sum256(e.Serialize())
	return hex.EncodeToString(h[:])
}

// Check verifies the id and the BIP-340 signature.
func (e *Event) Check() error {
	if got := e.ComputeID(); got != e.ID {
		return fmt.Errorf("id mismatch: event says %s, content hashes to %s", short(e.ID), short(got))
	}
	pk, err := hex.DecodeString(e.PubKey)
	if err != nil || len(pk) != 32 {
		return errors.New("bad pubkey")
	}
	sig, err := hex.DecodeString(e.Sig)
	if err != nil || len(sig) != 64 {
		return errors.New("bad sig encoding")
	}
	pub, err := schnorr.ParsePubKey(pk)
	if err != nil {
		return fmt.Errorf("bad pubkey: %w", err)
	}
	s, err := schnorr.ParseSignature(sig)
	if err != nil {
		return fmt.Errorf("bad sig: %w", err)
	}
	id, _ := hex.DecodeString(e.ID)
	if !s.Verify(id, pub) {
		return errors.New("signature does not verify")
	}
	return nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

// ParseEvent decodes one event and rejects unknown shapes early.
func ParseEvent(b []byte) (*Event, error) {
	var e Event
	d := json.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(&e); err != nil {
		return nil, fmt.Errorf("not a Nostr event: %w", err)
	}
	if len(e.ID) != 64 || len(e.PubKey) != 64 || len(e.Sig) != 128 {
		return nil, errors.New("not a signed Nostr event (id/pubkey/sig missing or wrong length)")
	}
	if e.Tags == nil {
		e.Tags = [][]string{}
	}
	return &e, nil
}

// PubKeyHex accepts a 64-char hex key or an npub (NIP-19).
func PubKeyHex(s string) (string, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "nostr:"))
	if strings.HasPrefix(strings.ToLower(s), "npub1") {
		hrp, data, err := Bech32Decode(s)
		if err != nil {
			return "", err
		}
		if hrp != "npub" || len(data) != 32 {
			return "", fmt.Errorf("%q is not an npub", s)
		}
		return hex.EncodeToString(data), nil
	}
	if b, err := hex.DecodeString(s); err != nil || len(b) != 32 {
		return "", fmt.Errorf("%q is neither an npub nor a 64-char hex key", s)
	}
	return strings.ToLower(s), nil
}
