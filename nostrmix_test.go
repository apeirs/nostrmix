package nostrmix_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/apeirs/nostrmix/gateway"
	"github.com/apeirs/nostrmix/internal/fakes"
	"github.com/apeirs/nostrmix/mixnet"
	"github.com/apeirs/nostrmix/nostr"
	"github.com/coder/websocket"
)

// world wires a fake mixnet: SOCKS proxy -> {DoH at 1.1.1.1, relay "relay.test" at 10.0.0.9}.
type world struct {
	ca    *fakes.CA
	socks *fakes.SOCKS
	relay *fakes.Relay
	ev    *nostr.Event
}

func signedEvent(t *testing.T) *nostr.Event {
	// A real event fetched from a public relay (see nostr/testdata).
	b, err := readFirstLine("nostr/testdata/real-events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := nostr.ParseEvent(b)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ca := fakes.NewCA()
	ev := signedEvent(t)
	evJSON, _ := json.Marshal(ev)
	broken := strings.Replace(string(evJSON), `"content":"`, `"content":"tampered `, 1)
	doh := fakes.DoH(ca, "1.1.1.1", map[string][]string{"relay.test": {"10.0.0.9"}})
	r := fakes.StartRelay(ca, "relay.test", evJSON, json.RawMessage(broken))
	s := fakes.NewSOCKS(map[string]string{
		"1.1.1.1:443":    doh,
		"10.0.0.9:443":   r.Addr,
		"relay.test:443": r.Addr,
	})
	t.Cleanup(func() { s.Close(); r.Close() })
	return &world{ca: ca, socks: s, relay: r, ev: ev}
}

func (w *world) client(dns string) *nostr.Client {
	d := &mixnet.Dialer{Proxy: w.socks.Addr, DNS: dns, RootCAs: w.ca.Pool, Resolvers: []string{"1.1.1.1"}, Timeout: 5 * time.Second}
	return &nostr.Client{D: d, RootCAs: w.ca.Pool, Compress: true}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func startGateway(t *testing.T, g *gateway.Gateway) string {
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// An unmodified client talks to ws://gateway/relay.test; the relay gets the
// messages, the client gets events + EOSE and OK, and every byte went through
// the SOCKS proxy (DoH lookup, then a CONNECT by IPv4).
func TestGatewayRelaysThroughMixnetOnly(t *testing.T) {
	w := newWorld(t)
	addr := startGateway(t, &gateway.Gateway{Client: w.client(mixnet.DNSDoH)})
	h := http.Header{}
	h.Set("Origin", "https://webclient.example")
	h.Set("Cookie", "session=secret")
	h.Set("User-Agent", "SomeClient/1.2.3 (Linux; fingerprintable)")
	c, _, err := websocket.Dial(ctx(t), "ws://"+addr+"/relay.test", &websocket.DialOptions{HTTPHeader: h})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	write := func(v any) {
		b, _ := json.Marshal(v)
		if err := c.Write(ctx(t), websocket.MessageText, b); err != nil {
			t.Fatal(err)
		}
	}
	read := func() []json.RawMessage {
		_, b, err := c.Read(ctx(t))
		if err != nil {
			t.Fatal(err)
		}
		var arr []json.RawMessage
		json.Unmarshal(b, &arr)
		return arr
	}
	write([]any{"REQ", "s1", map[string]any{"kinds": []int{1}}})
	var types []string
	for i := 0; i < 3; i++ {
		var typ string
		json.Unmarshal(read()[0], &typ)
		types = append(types, typ)
	}
	if strings.Join(types, ",") != "EVENT,EVENT,EOSE" {
		t.Fatalf("client got %v", types)
	}
	write([]any{"EVENT", w.ev})
	if ok := read(); len(ok) < 3 || string(ok[2]) != "true" {
		t.Fatalf("no OK: %s", ok)
	}

	// The proxy saw only the DoH resolver and the relay's IPv4, nothing by name.
	var seen []string
	for _, r := range w.socks.Seen() {
		seen = append(seen, r.String())
	}
	if got := strings.Join(seen, " "); got != "1.1.1.1:443(atyp 1) 10.0.0.9:443(atyp 1)" {
		t.Fatalf("SOCKS CONNECTs: %s", got)
	}
	// The relay saw none of the client's identifying headers.
	hdrs, msgs, _ := w.relay.Seen()
	if len(hdrs) != 1 {
		t.Fatalf("%d handshakes", len(hdrs))
	}
	for _, k := range []string{"Origin", "Cookie", "X-Forwarded-For", "Forwarded"} {
		if v := hdrs[0].Get(k); v != "" {
			t.Fatalf("relay saw %s: %s", k, v)
		}
	}
	if ua := hdrs[0].Get("User-Agent"); ua != nostr.UserAgent {
		t.Fatalf("relay saw User-Agent %q", ua)
	}
	if len(msgs) != 2 {
		t.Fatalf("relay got %d messages", len(msgs))
	}
}

func TestGatewayExitResolvesNames(t *testing.T) {
	w := newWorld(t)
	addr := startGateway(t, &gateway.Gateway{Client: w.client(mixnet.DNSExit)})
	c, _, err := websocket.Dial(ctx(t), "ws://"+addr+"/wss://relay.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Close(websocket.StatusNormalClosure, "")
	s := w.socks.Seen()
	if len(s) != 1 || s[0].ATYP != 3 || s[0].Host != "relay.test" {
		t.Fatalf("want one CONNECT by name, got %v", s)
	}
}

// With the mixnet client down, the gateway answers 502 and never opens a
// direct connection to the relay.
func TestNoClearnetFallback(t *testing.T) {
	w := newWorld(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	cl := &nostr.Client{D: &mixnet.Dialer{Proxy: dead, DNS: mixnet.DNSExit}, RootCAs: w.ca.Pool}
	addr := startGateway(t, &gateway.Gateway{Client: cl})
	_, resp, err := websocket.Dial(ctx(t), "ws://"+addr+"/relay.test", nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("want 502, got %v %v", resp, err)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "refusing to fall back") {
		t.Fatalf("body: %s", body)
	}
	if _, _, n := w.relay.Seen(); n != 0 {
		t.Fatalf("relay was contacted %d times", n)
	}
}

func TestDNSRebindingGuardAndRules(t *testing.T) {
	w := newWorld(t)
	g := &gateway.Gateway{Client: w.client(mixnet.DNSExit), Only: map[string]bool{"relay.test": true}}
	addr := startGateway(t, g)
	req, _ := http.NewRequest("GET", "http://"+addr+"/relay.test", nil)
	req.Host = "evil.example:7777"
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("rebinding: %v %v", resp, err)
	}
	for path, want := range map[string]string{
		"/other.relay":         "not in the --only list",
		"/relay.test:8443":     "port 8443 is not allowed",
		"/ws://relay.test":     "refusing plain ws://",
		"/":                    "", // help page
		"/relay.test?x=1#frag": "connect with a WebSocket",
	} {
		resp, err := http.Get("http://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		if want == "" {
			if resp.StatusCode != 200 || !strings.Contains(string(b), "Nym mixnet") {
				t.Fatalf("help page: %d %s", resp.StatusCode, b)
			}
			continue
		}
		if !strings.Contains(string(b), want) {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, b)
		}
	}
	if s := w.socks.Seen(); len(s) != 0 {
		t.Fatalf("refused requests reached the proxy: %v", s)
	}
}

func TestTargetMapping(t *testing.T) {
	def, _ := nostr.RelayURL("nos.lol", false)
	g := &gateway.Gateway{Default: def}
	for in, want := range map[string]string{
		"/relay.damus.io":          "wss://relay.damus.io/",
		"/nos.lol/inbox?x=1":       "wss://nos.lol/inbox?x=1",
		"/wss://relay.example.com": "wss://relay.example.com/",
		"/wss:/relay.example.com":  "wss://relay.example.com/",
		"/":                        "wss://nos.lol/",
	} {
		u, _ := url.Parse("http://127.0.0.1:7777" + in)
		got, err := g.Target(u)
		if err != nil || got.String() != want {
			t.Fatalf("%s -> %v %v", in, got, err)
		}
	}
}

func TestNIP11ThroughGateway(t *testing.T) {
	w := newWorld(t)
	addr := startGateway(t, &gateway.Gateway{Client: w.client(mixnet.DNSDoH)})
	req, _ := http.NewRequest("GET", "http://"+addr+"/relay.test", nil)
	req.Header.Set("Accept", "application/nostr+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "fake relay") || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("%d %s %v", resp.StatusCode, b, resp.Header)
	}
}

// The relay's close code and reason reach the client.
func TestCloseIsPropagated(t *testing.T) {
	w := newWorld(t)
	addr := startGateway(t, &gateway.Gateway{Client: w.client(mixnet.DNSDoH)})
	c, _, err := websocket.Dial(ctx(t), "ws://"+addr+"/relay.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Write(ctx(t), websocket.MessageText, []byte(`["BYE",""]`))
	_, _, err = c.Read(ctx(t))
	var ce websocket.CloseError
	if !asClose(err, &ce) || ce.Code != 4000 || ce.Reason != "bye from relay" {
		t.Fatalf("got %v", err)
	}
}

// The CLI path: Req counts the tampered event as invalid, Publish gets OK.
func TestReqAndPublishDirect(t *testing.T) {
	w := newWorld(t)
	cl := w.client(mixnet.DNSDoH)
	u, _ := nostr.RelayURL("relay.test", false)
	ws, err := cl.Dial(ctx(t), u)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	var good int
	res, err := nostr.Req(ctx(t), ws, "x", []json.RawMessage{json.RawMessage(`{"limit":2}`)}, true, func(ev *nostr.Event, err error) {
		if err == nil {
			good++
		}
	})
	if err != nil || !res.EOSE || res.Events != 1 || res.Invalid != 1 || good != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	ok, _, err := nostr.Publish(ctx(t), ws, w.ev)
	if err != nil || !ok {
		t.Fatalf("publish: %v %v", ok, err)
	}
	doc, err := cl.Info(ctx(t), u)
	if err != nil || !strings.Contains(string(doc), "supported_nips") {
		t.Fatalf("info: %s %v", doc, err)
	}
}
