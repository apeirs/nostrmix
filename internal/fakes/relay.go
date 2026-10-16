package fakes

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"sync"

	"github.com/coder/websocket"
)

// Relay is a minimal Nostr relay over TLS: REQ answers with Events then EOSE,
// EVENT answers OK (accepting everything), NIP-11 on GET with the nostr Accept.
type Relay struct {
	Addr   string
	Events []json.RawMessage
	Info   string

	mu      sync.Mutex
	Headers []http.Header // handshake headers seen
	Got     []json.RawMessage
	conns   int
	ln      net.Listener
}

// StartRelay serves a fake relay with a certificate for name.
func StartRelay(ca *CA, name string, events ...json.RawMessage) *Relay {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{ca.Leaf(name)}})
	if err != nil {
		panic(err)
	}
	r := &Relay{Addr: ln.Addr().String(), Events: events, Info: `{"name":"fake relay","supported_nips":[1,11]}`, ln: ln}
	go http.Serve(ln, r)
	return r
}

func (r *Relay) Close() { r.ln.Close() }

// Seen returns the handshake headers and the messages received so far.
func (r *Relay) Seen() ([]http.Header, []json.RawMessage, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]http.Header(nil), r.Headers...), append([]json.RawMessage(nil), r.Got...), r.conns
}

func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.conns++
	r.Headers = append(r.Headers, req.Header.Clone())
	r.mu.Unlock()
	if req.Header.Get("Upgrade") == "" {
		w.Header().Set("Content-Type", "application/nostr+json")
		w.Write([]byte(r.Info))
		return
	}
	c, err := websocket.Accept(w, req, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer c.CloseNow()
	ctx := context.Background()
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		r.mu.Lock()
		r.Got = append(r.Got, data)
		r.mu.Unlock()
		var arr []json.RawMessage
		if json.Unmarshal(data, &arr) != nil || len(arr) < 2 {
			continue
		}
		var typ string
		json.Unmarshal(arr[0], &typ)
		switch typ {
		case "REQ":
			var sub string
			json.Unmarshal(arr[1], &sub)
			for _, ev := range r.Events {
				b, _ := json.Marshal([]any{"EVENT", sub, ev})
				c.Write(ctx, websocket.MessageText, b)
			}
			b, _ := json.Marshal([]any{"EOSE", sub})
			c.Write(ctx, websocket.MessageText, b)
		case "EVENT":
			var ev struct {
				ID string `json:"id"`
			}
			json.Unmarshal(arr[1], &ev)
			b, _ := json.Marshal([]any{"OK", ev.ID, true, ""})
			c.Write(ctx, websocket.MessageText, b)
		case "BYE":
			c.Close(4000, "bye from relay")
			return
		}
	}
}
