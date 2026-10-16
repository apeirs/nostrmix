// Package gateway is a local Nostr relay gateway: an unmodified Nostr client
// connects to ws://127.0.0.1:7777/<relay-host> and nostrmix opens
// wss://<relay-host> through the Nym mixnet, then copies WebSocket messages
// both ways without reading or changing them.
//
// The relay sees a Nym exit gateway's IP, never yours. Browser web clients can
// use it too, because browsers allow ws:// to loopback from https pages.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apeirs/nostrmix/nostr"
	"github.com/coder/websocket"
)

// Gateway serves the local relay endpoint.
type Gateway struct {
	Client *nostr.Client
	// Default relay for connections to "/" (nil: "/" only shows the help page).
	Default *url.URL
	// Ports allowed upstream (default {443}).
	Ports map[int]bool
	// Only, if set, is the list of relay hosts that may be reached.
	Only map[string]bool
	// AllowPlain permits ws:// upstreams (clear text at the exit gateway).
	AllowPlain bool
	// OriginPatterns restricts which web origins may connect (nil = any).
	OriginPatterns []string
	// Hosts accepted in the Host header besides loopback names (DNS-rebinding guard).
	Hosts []string
	// DialTimeout for the upstream WebSocket handshake over the mixnet.
	DialTimeout time.Duration
	// PingEvery keeps idle upstream streams alive (0 = 30s, <0 = off).
	PingEvery time.Duration
	Log       func(format string, args ...any)

	nextID                atomic.Int64
	active, total, failed atomic.Int64
	msgsUp, msgsDown      atomic.Int64
	mu                    sync.Mutex
	perRelay              map[string]int
}

func (g *Gateway) logf(format string, args ...any) {
	if g.Log != nil {
		g.Log(format, args...)
	}
}

// ErrTarget is a bad or forbidden relay in the request path.
type ErrTarget struct{ msg string }

func (e *ErrTarget) Error() string { return e.msg }

// Target maps a request path to the upstream relay URL:
//
//	/relay.damus.io            -> wss://relay.damus.io/
//	/nos.lol/inbox?x=1         -> wss://nos.lol/inbox?x=1
//	/wss://relay.example.com   -> wss://relay.example.com/
//	/                          -> the default relay, if set
func (g *Gateway) Target(u *url.URL) (*url.URL, error) {
	p := strings.TrimPrefix(u.Path, "/")
	plain := false
	for _, pre := range []string{"wss://", "wss:/", "ws://", "ws:/"} {
		if strings.HasPrefix(p, pre) {
			plain = strings.HasPrefix(pre, "ws:")
			p = p[len(pre):]
			break
		}
	}
	if p == "" {
		if g.Default == nil {
			return nil, &ErrTarget{"no relay in the path and no --default relay; connect to ws://127.0.0.1:PORT/<relay-host>"}
		}
		t := *g.Default
		return &t, g.allowed(&t)
	}
	scheme := "wss://"
	if plain {
		scheme = "ws://"
	}
	t, err := nostr.RelayURL(scheme+p, g.AllowPlain)
	if err != nil {
		return nil, &ErrTarget{err.Error()}
	}
	t.RawQuery = u.RawQuery
	return t, g.allowed(t)
}

func (g *Gateway) allowed(t *url.URL) error {
	ports := g.Ports
	if ports == nil {
		ports = map[int]bool{443: true}
	}
	if !ports[nostr.Port(t)] {
		return &ErrTarget{fmt.Sprintf("port %d is not allowed (allowed: %s); see --allow-port", nostr.Port(t), portList(ports))}
	}
	if t.Scheme == "ws" && !g.AllowPlain {
		return &ErrTarget{"plain ws:// upstreams are off (the exit gateway would read them); see --allow-plain"}
	}
	if g.Only != nil && !g.Only[strings.ToLower(t.Hostname())] {
		return &ErrTarget{fmt.Sprintf("relay %s is not in the --only list", t.Hostname())}
	}
	return nil
}

func portList(m map[int]bool) string {
	var ps []string
	for p, ok := range m {
		if ok {
			ps = append(ps, strconv.Itoa(p))
		}
	}
	sort.Strings(ps)
	return strings.Join(ps, ",")
}

// hostOK guards against DNS rebinding: a web page on evil.example that
// rebinds its name to 127.0.0.1 still sends "Host: evil.example".
func (g *Gateway) hostOK(h string) bool {
	host := h
	if hh, _, err := net.SplitHostPort(h); err == nil {
		host = hh
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	for _, a := range g.Hosts {
		if strings.EqualFold(a, host) {
			return true
		}
	}
	return false
}

func isUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !g.hostOK(r.Host) {
		http.Error(w, "nostrmix: Host header not allowed (DNS-rebinding guard); see --host", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Accept")
		w.Header().Set("Access-Control-Allow-Methods", "GET")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.URL.Path == "/" && !isUpgrade(r) && !strings.Contains(r.Header.Get("Accept"), "application/nostr+json") {
		g.help(w)
		return
	}
	if r.URL.Path == "/stats" && !isUpgrade(r) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(g.Stats())
		return
	}
	t, err := g.Target(r.URL)
	if err != nil {
		http.Error(w, "nostrmix: "+err.Error(), http.StatusBadRequest)
		return
	}
	if isUpgrade(r) {
		g.proxy(w, r, t)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "application/nostr+json") {
		g.nip11(w, r, t)
		return
	}
	http.Error(w, "nostrmix: this is a Nostr relay gateway; connect with a WebSocket to ws://"+r.Host+r.URL.Path, http.StatusBadRequest)
}

func (g *Gateway) nip11(w http.ResponseWriter, r *http.Request, t *url.URL) {
	ctx, cancel := context.WithTimeout(r.Context(), g.dialTimeout())
	defer cancel()
	doc, err := g.Client.Info(ctx, t)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if err != nil {
		g.logf("nip11 %s: %v", t.Host, err)
		http.Error(w, "nostrmix: "+err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/nostr+json")
	_, _ = w.Write(doc)
}

func (g *Gateway) dialTimeout() time.Duration {
	if g.DialTimeout > 0 {
		return g.DialTimeout
	}
	return 90 * time.Second
}

func (g *Gateway) proxy(w http.ResponseWriter, r *http.Request, t *url.URL) {
	id := g.nextID.Add(1)
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "-"
	}
	t0 := time.Now()
	// Dial the relay first, so the client sees "connected" only when the
	// mixnet path really works; a failure becomes an HTTP 502 it can retry.
	dctx, cancel := context.WithTimeout(r.Context(), g.dialTimeout())
	up, err := g.Client.Dial(dctx, t)
	cancel()
	if err != nil {
		g.failed.Add(1)
		g.logf("#%d %s -> %s FAILED after %.1fs: %v", id, origin, t.Host, time.Since(t0).Seconds(), err)
		http.Error(w, "nostrmix: "+err.Error(), http.StatusBadGateway)
		return
	}
	down, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: g.OriginPatterns == nil,
		OriginPatterns:     g.OriginPatterns,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		up.Close(websocket.StatusGoingAway, "")
		g.logf("#%d %s -> %s refused: %v", id, origin, t.Host, err)
		return
	}
	down.SetReadLimit(nostr.ReadLimit)
	g.active.Add(1)
	g.total.Add(1)
	g.mu.Lock()
	if g.perRelay == nil {
		g.perRelay = map[string]int{}
	}
	g.perRelay[t.Host]++
	g.mu.Unlock()
	defer g.active.Add(-1)
	g.logf("#%d %s -> %s open (mixnet handshake %.1fs)", id, origin, t.Host, time.Since(t0).Seconds())

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	var nUp, nDown atomic.Int64
	type end struct {
		from string
		err  error
	}
	ends := make(chan end, 3)
	go func() { ends <- end{"client", pump(ctx, down, up, &nUp, &g.msgsUp)} }()
	go func() { ends <- end{"relay", pump(ctx, up, down, &nDown, &g.msgsDown)} }()
	if every := g.pingEvery(); every > 0 {
		go func() {
			tk := time.NewTicker(every)
			defer tk.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tk.C:
					pctx, c := context.WithTimeout(ctx, every*2)
					err := up.Ping(pctx)
					c()
					if err != nil && ctx.Err() == nil {
						ends <- end{"relay", fmt.Errorf("keepalive ping over the mixnet failed: %w", err)}
						return
					}
				}
			}
		}()
	}
	e := <-ends
	code, reason := closeOf(e.err)
	if e.from == "client" {
		_ = up.Close(code, reason)
		down.CloseNow()
	} else {
		_ = down.Close(code, reason)
		up.CloseNow()
	}
	stop()
	g.logf("#%d %s -> %s closed by %s after %s (%d msgs up, %d down): %s", id, origin, t.Host, e.from,
		time.Since(t0).Round(time.Second), nUp.Load(), nDown.Load(), describe(e.err))
}

func (g *Gateway) pingEvery() time.Duration {
	if g.PingEvery == 0 {
		return 30 * time.Second
	}
	return g.PingEvery
}

// pump copies messages from src to dst, keeping their type (text/binary).
func pump(ctx context.Context, src, dst *websocket.Conn, n, total *atomic.Int64) error {
	for {
		typ, data, err := src.Read(ctx)
		if err != nil {
			return err
		}
		wctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err = dst.Write(wctx, typ, data)
		cancel()
		if err != nil {
			return fmt.Errorf("forwarding: %w", err)
		}
		n.Add(1)
		total.Add(1)
	}
}

// closeOf turns the error that ended one side into a close frame for the other.
func closeOf(err error) (websocket.StatusCode, string) {
	var ce websocket.CloseError
	if errors.As(err, &ce) {
		switch ce.Code {
		case websocket.StatusNoStatusRcvd, websocket.StatusAbnormalClosure, websocket.StatusTLSHandshake:
		default:
			return ce.Code, ce.Reason
		}
	}
	if err != nil && strings.Contains(err.Error(), "keepalive") {
		return websocket.StatusGoingAway, "nostrmix: mixnet stream to the relay went quiet"
	}
	return websocket.StatusGoingAway, ""
}

func describe(err error) string {
	var ce websocket.CloseError
	if errors.As(err, &ce) {
		if ce.Reason != "" {
			return fmt.Sprintf("close %d %q", ce.Code, ce.Reason)
		}
		return fmt.Sprintf("close %d", ce.Code)
	}
	if err == nil {
		return "ok"
	}
	return err.Error()
}

// Stats is what /stats returns.
type Stats struct {
	Active       int64          `json:"active"`
	Total        int64          `json:"total"`
	FailedDials  int64          `json:"failed_dials"`
	MessagesUp   int64          `json:"messages_up"`
	MessagesDown int64          `json:"messages_down"`
	Relays       map[string]int `json:"relays"`
}

func (g *Gateway) Stats() Stats {
	g.mu.Lock()
	rel := make(map[string]int, len(g.perRelay))
	for k, v := range g.perRelay {
		rel[k] = v
	}
	g.mu.Unlock()
	return Stats{g.active.Load(), g.total.Load(), g.failed.Load(), g.msgsUp.Load(), g.msgsDown.Load(), rel}
}

func (g *Gateway) help(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	st := g.Stats()
	def := "(none)"
	if g.Default != nil {
		def = g.Default.String()
	}
	fmt.Fprintf(w, `nostrmix: Nostr relays through the Nym mixnet

Add relays to your Nostr client as
  ws://<this address>/<relay host>        e.g. ws://127.0.0.1:7777/nos.lol
The relay sees a Nym exit gateway's IP, not yours. TLS to the relay is end to end.

default relay for "/": %s
sessions: %d active, %d total, %d failed dials
messages: %d client->relay, %d relay->client
`, def, st.Active, st.Total, st.FailedDials, st.MessagesUp, st.MessagesDown)
}
