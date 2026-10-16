// Command nostrmix: Nostr relay traffic over the Nym mixnet.
//
//	nostrmix nym setup              start nym-socks5-client on a random active exit gateway
//	nostrmix serve                  local relay gateway: ws://127.0.0.1:7777/<relay> -> mixnet -> wss://<relay>
//	nostrmix req | publish | info   talk to relays directly over the mixnet
//	nostrmix probe                  which relays accept Nym exit traffic, and how fast
//	nostrmix ip                     which IP do relays see? (a Nym exit gateway)
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/apeirs/nostrmix/gateway"
	"github.com/apeirs/nostrmix/mixnet"
	"github.com/apeirs/nostrmix/nostr"
	"github.com/coder/websocket"
)

const version = "0.1.0"

var start = time.Now()

func tracef(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[%7.2fs] "+format+"\n", append([]any{time.Since(start).Seconds()}, args...)...)
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s "+format+"\n", append([]any{time.Now().Format("15:04:05")}, args...)...)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "nostrmix:", err)
	os.Exit(1)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// common flags shared by network commands.
type common struct {
	proxy, dns       string
	verbose, jsonOut bool
	compress         bool
	timeout          time.Duration
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.proxy, "proxy", envOr("NOSTRMIX_PROXY", "127.0.0.1:1080"), "nym-socks5-client SOCKS5 address ($NOSTRMIX_PROXY)")
	fs.StringVar(&c.dns, "dns", envOr("NOSTRMIX_DNS", mixnet.DNSDoH), "name resolution: doh (DoH over the mixnet, connect by IPv4) or exit (exit gateway resolves)")
	fs.BoolVar(&c.verbose, "v", false, "trace every mixnet step to stderr")
	fs.BoolVar(&c.jsonOut, "json", false, "JSON output")
	fs.BoolVar(&c.compress, "compress", true, "ask relays for permessage-deflate (fewer mixnet packets)")
	fs.DurationVar(&c.timeout, "timeout", 3*time.Minute, "overall timeout for the command")
}

func (c *common) dialer() *mixnet.Dialer {
	proxy, err := mixnet.ParseProxy(c.proxy)
	if err != nil {
		die(err)
	}
	if c.dns != mixnet.DNSDoH && c.dns != mixnet.DNSExit {
		die(fmt.Errorf("--dns must be doh or exit"))
	}
	d := &mixnet.Dialer{Proxy: proxy, DNS: c.dns}
	if c.verbose {
		d.Trace = tracef
	}
	return d
}

func (c *common) client() *nostr.Client {
	return &nostr.Client{D: c.dialer(), Compress: c.compress}
}

func (c *common) ctx() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	return ctx, func() { stop(); cancel() }
}

func (c *common) out(v any, human string) {
	if c.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
		return
	}
	fmt.Println(human)
}

func usage() {
	fmt.Fprint(os.Stderr, `nostrmix `+version+`: Nostr relays through the Nym mixnet

Mixnet client (official nym-socks5-client):
  nostrmix nym setup [--binary PATH] [--port 1080]   init on a random active exit gateway, then start
  nostrmix nym start | stop | status | exits

Local relay gateway for any Nostr client (desktop, mobile on the same host, browser web clients):
  nostrmix serve [--listen 127.0.0.1:7777] [--default RELAY] [--only R1,R2] [--allow-port 443]
     then use relay URLs like  ws://127.0.0.1:7777/relay.damus.io

Talk to relays directly over the mixnet:
  nostrmix req RELAY... [--kinds 1] [--authors npub..] [--limit 20] [--since 24h] [--filter JSON]
                                   fetch events (JSON lines), ids and signatures checked
  nostrmix publish RELAY... EVENT.json|-   send a signed event (from your client, nak, a signer)
  nostrmix info RELAY              NIP-11 relay information document
  nostrmix probe [RELAY...]        connect + REQ through the mixnet, report which relays work
  nostrmix ip                      which IP do relays see? (should be a Nym exit gateway)

Common flags: --proxy 127.0.0.1:1080 --dns doh|exit -v --json --timeout 3m
nostrmix never holds a private key, and there is no clearnet fallback: if the
mixnet client is down, nostrmix refuses to connect.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "nym":
		cmdNym(args)
	case "serve", "gateway":
		cmdServe(args)
	case "req":
		cmdReq(args)
	case "publish":
		cmdPublish(args)
	case "info":
		cmdInfo(args)
	case "probe":
		cmdProbe(args)
	case "ip":
		cmdIP(args)
	case "version", "--version":
		fmt.Println("nostrmix", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "nostrmix: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

// parse parses flags that may appear before or after positional arguments.
func parse(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			os.Exit(2)
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func relayURLs(args []string, allowPlain bool) []*url.URL {
	if len(args) == 0 {
		die(errors.New("give at least one relay, e.g. relay.damus.io"))
	}
	var us []*url.URL
	for _, a := range args {
		u, err := nostr.RelayURL(a, allowPlain)
		if err != nil {
			die(err)
		}
		us = append(us, u)
	}
	return us
}

// ---------------------------------------------------------------- serve

func cmdServe(args []string) {
	var c common
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	c.register(fs)
	listen := fs.String("listen", envOr("NOSTRMIX_LISTEN", "127.0.0.1:7777"), "local address ($NOSTRMIX_LISTEN)")
	def := fs.String("default", "", "relay used for connections to \"/\" (optional)")
	only := fs.String("only", "", "comma-separated relay hosts; refuse all others")
	ports := fs.String("allow-port", "443", "comma-separated upstream ports allowed (the Nym exit policy must allow them too)")
	plain := fs.Bool("allow-plain", false, "allow ws:// upstreams (clear text at the exit gateway)")
	origins := fs.String("origin", "", "comma-separated web origins allowed to connect, e.g. coracle.social (default: any)")
	hosts := fs.String("host", "", "extra Host header names to accept besides loopback (DNS-rebinding guard)")
	public := fs.Bool("public", false, "allow listening on a non-loopback address (anyone who can reach it uses your mixnet client)")
	dialTO := fs.Duration("dial-timeout", 90*time.Second, "upstream handshake timeout over the mixnet")
	parse(fs, args)

	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		die(fmt.Errorf("--listen: %w", err))
	}
	if ip := net.ParseIP(host); (ip == nil && host != "localhost") || (ip != nil && !ip.IsLoopback()) {
		if !*public {
			die(fmt.Errorf("refusing to listen on %s: not a loopback address (pass --public if you really mean it)", host))
		}
	}
	g := &gateway.Gateway{Client: c.client(), AllowPlain: *plain, DialTimeout: *dialTO, Log: logf, Hosts: splitList(*hosts)}
	if *def != "" {
		if g.Default, err = nostr.RelayURL(*def, *plain); err != nil {
			die(err)
		}
	}
	g.Ports = map[int]bool{}
	for _, p := range splitList(*ports) {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			die(fmt.Errorf("--allow-port: bad port %q", p))
		}
		g.Ports[n] = true
	}
	if *only != "" {
		g.Only = map[string]bool{}
		for _, h := range splitList(*only) {
			u, err := nostr.RelayURL(h, true)
			if err != nil {
				die(err)
			}
			g.Only[strings.ToLower(u.Hostname())] = true
		}
	}
	if *origins != "" {
		g.OriginPatterns = splitList(*origins)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		die(err)
	}
	if conn, err := net.DialTimeout("tcp", g.Client.D.(*mixnet.Dialer).Proxy, 2*time.Second); err != nil {
		logf("WARNING: no SOCKS5 proxy at %s yet (start it with `nostrmix nym setup` or `nostrmix nym start`); connections will fail until it is up. There is no clearnet fallback.", c.proxy)
	} else {
		conn.Close()
	}
	addr := ln.Addr().String()
	logf("nostrmix %s gateway on ws://%s  ->  Nym mixnet (socks5 %s, dns=%s)  ->  relays", version, addr, c.proxy, c.dns)
	logf("add relays to your client as ws://%s/<relay host>, e.g. ws://%s/nos.lol", addr, addr)
	if g.Default != nil {
		logf("ws://%s/ goes to %s", addr, g.Default)
	}
	srv := &http.Server{Handler: g, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		die(err)
	}
	st := g.Stats()
	logf("stopped: %d sessions, %d failed dials, %d msgs up, %d down", st.Total, st.FailedDials, st.MessagesUp, st.MessagesDown)
}

// ---------------------------------------------------------------- req

// buildFilter turns CLI flags into one NIP-01 filter.
func buildFilter(kinds, authors, ids string, limit int, since, until, tags, search string, now time.Time) (json.RawMessage, error) {
	f := map[string]any{}
	if kinds != "" {
		var ks []int
		for _, k := range splitList(kinds) {
			n, err := strconv.Atoi(k)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("--kinds: bad kind %q", k)
			}
			ks = append(ks, n)
		}
		f["kinds"] = ks
	}
	if authors != "" {
		var as []string
		for _, a := range splitList(authors) {
			h, err := nostr.PubKeyHex(a)
			if err != nil {
				return nil, fmt.Errorf("--authors: %w", err)
			}
			as = append(as, h)
		}
		f["authors"] = as
	}
	if ids != "" {
		f["ids"] = splitList(ids)
	}
	if limit > 0 {
		f["limit"] = limit
	}
	for name, v := range map[string]string{"since": since, "until": until} {
		if v == "" {
			continue
		}
		ts, err := parseTime(v, now)
		if err != nil {
			return nil, fmt.Errorf("--%s: %w", name, err)
		}
		f[name] = ts
	}
	if tags != "" {
		for _, t := range splitList(tags) {
			k, v, ok := strings.Cut(t, "=")
			if !ok || len(k) != 1 {
				return nil, fmt.Errorf("--tag: want x=value with a one-letter tag name, got %q", t)
			}
			key := "#" + k
			prev, _ := f[key].([]string)
			f[key] = append(prev, v)
		}
	}
	if search != "" {
		f["search"] = search
	}
	return json.Marshal(f)
}

// parseTime accepts a unix timestamp or a duration ago ("24h", "90m", "7d").
func parseTime(s string, now time.Time) (int64, error) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("bad time %q", s)
		}
		return now.Add(-time.Duration(n) * 24 * time.Hour).Unix(), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("bad time %q (unix seconds or a duration like 24h, 7d)", s)
	}
	return now.Add(-d).Unix(), nil
}

func cmdReq(args []string) {
	var c common
	fs := flag.NewFlagSet("req", flag.ExitOnError)
	c.register(fs)
	kinds := fs.String("kinds", "", "comma-separated kinds")
	authors := fs.String("authors", "", "comma-separated npubs or hex pubkeys")
	ids := fs.String("ids", "", "comma-separated event ids")
	limit := fs.Int("limit", 20, "max events per relay (0 = no limit)")
	since := fs.String("since", "", "unix time or duration ago (24h, 7d)")
	until := fs.String("until", "", "unix time or duration ago")
	tags := fs.String("tag", "", "tag filters, comma-separated x=value (e.g. t=nym,p=<hex>)")
	search := fs.String("search", "", "NIP-50 search (only relays that support it)")
	raw := fs.String("filter", "", "a raw NIP-01 filter as JSON (replaces the flags above)")
	noVerify := fs.Bool("no-verify", false, "don't check event ids and signatures")
	keepBad := fs.Bool("keep-invalid", false, "print events that fail the check (marked on stderr)")
	plain := fs.Bool("allow-plain", false, "allow ws:// relays")
	relays := relayURLs(parse(fs, args), *plain)

	var filter json.RawMessage
	var err error
	if *raw != "" {
		if !json.Valid([]byte(*raw)) || !strings.HasPrefix(strings.TrimSpace(*raw), "{") {
			die(errors.New("--filter must be a JSON object"))
		}
		filter = json.RawMessage(*raw)
	} else if filter, err = buildFilter(*kinds, *authors, *ids, *limit, *since, *until, *tags, *search, time.Now()); err != nil {
		die(err)
	}
	cl := c.client()
	ctx, cancel := c.ctx()
	defer cancel()

	var mu sync.Mutex
	seen := map[string]bool{}
	out := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	type row struct {
		relay string
		res   nostr.ReqResult
		err   error
		secs  float64
	}
	rows := make([]row, len(relays))
	var wg sync.WaitGroup
	for i, u := range relays {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			r := row{relay: u.Host}
			defer func() { r.secs = time.Since(t0).Seconds(); rows[i] = r }()
			ws, err := cl.Dial(ctx, u)
			if err != nil {
				r.err = err
				return
			}
			defer ws.Close(websocket.StatusNormalClosure, "")
			r.res, r.err = nostr.Req(ctx, ws, "nostrmix", []json.RawMessage{filter}, !*noVerify, func(ev *nostr.Event, verr error) {
				mu.Lock()
				defer mu.Unlock()
				if verr != nil {
					fmt.Fprintf(os.Stderr, "INVALID event from %s: %v\n", u.Host, verr)
					if !*keepBad || ev == nil {
						return
					}
				}
				if seen[ev.ID] {
					return
				}
				seen[ev.ID] = true
				enc.Encode(ev)
			})
		}()
	}
	wg.Wait()
	out.Flush()
	ok := false
	for _, r := range rows {
		switch {
		case r.err != nil:
			fmt.Fprintf(os.Stderr, "%-28s FAILED after %.1fs: %v\n", r.relay, r.secs, r.err)
		default:
			ok = true
			end := "EOSE"
			if !r.res.EOSE {
				end = "CLOSED " + r.res.Closed
			}
			fmt.Fprintf(os.Stderr, "%-28s %d events (%d invalid) %s in %.1fs over the mixnet\n", r.relay, r.res.Events, r.res.Invalid, end, r.secs)
			for _, n := range r.res.Notices {
				fmt.Fprintf(os.Stderr, "%-28s NOTICE %s\n", r.relay, n)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "%d unique events\n", len(seen))
	if !ok {
		os.Exit(1)
	}
}

// ---------------------------------------------------------------- publish

func cmdPublish(args []string) {
	var c common
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	c.register(fs)
	noVerify := fs.Bool("no-verify", false, "send even if the id or signature does not check out")
	plain := fs.Bool("allow-plain", false, "allow ws:// relays")
	pos := parse(fs, args)
	if len(pos) < 2 {
		die(errors.New("usage: nostrmix publish RELAY... EVENT.json|-"))
	}
	src := pos[len(pos)-1]
	relays := relayURLs(pos[:len(pos)-1], *plain)
	var data []byte
	var err error
	if src == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, nostr.ReadLimit))
	} else {
		data, err = os.ReadFile(src)
	}
	if err != nil {
		die(err)
	}
	ev, err := nostr.ParseEvent(data)
	if err != nil {
		die(err)
	}
	if err := ev.Check(); err != nil {
		if !*noVerify {
			die(fmt.Errorf("event does not verify (%v); relays would reject it. --no-verify sends it anyway", err))
		}
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "event %s (kind %d) verified: id and BIP-340 signature OK\n", ev.ID, ev.Kind)
	}
	cl := c.client()
	ctx, cancel := c.ctx()
	defer cancel()
	res := make([]nostr.OK, len(relays))
	var wg sync.WaitGroup
	for i, u := range relays {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			r := nostr.OK{Relay: u.Host}
			defer func() { r.Seconds = time.Since(t0).Seconds(); res[i] = r }()
			ws, err := cl.Dial(ctx, u)
			if err != nil {
				r.Error = err.Error()
				return
			}
			defer ws.Close(websocket.StatusNormalClosure, "")
			pctx, pc := context.WithTimeout(ctx, 2*time.Minute)
			defer pc()
			r.Accepted, r.Message, err = nostr.Publish(pctx, ws, ev)
			if err != nil {
				r.Error = err.Error()
			}
		}()
	}
	wg.Wait()
	n := 0
	var sb strings.Builder
	tw := tabwriter.NewWriter(&sb, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "RELAY\tACCEPTED\tSECONDS\tMESSAGE")
	for _, r := range res {
		msg := r.Message
		if r.Error != "" {
			msg = "error: " + r.Error
		}
		if r.Accepted {
			n++
		}
		fmt.Fprintf(tw, "%s\t%v\t%.1f\t%s\n", r.Relay, r.Accepted, r.Seconds, msg)
	}
	tw.Flush()
	c.out(map[string]any{"id": ev.ID, "results": res}, strings.TrimRight(sb.String(), "\n")+fmt.Sprintf("\naccepted by %d of %d relays", n, len(res)))
	if n == 0 {
		os.Exit(1)
	}
}

// ---------------------------------------------------------------- info

func cmdInfo(args []string) {
	var c common
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	c.register(fs)
	plain := fs.Bool("allow-plain", false, "allow ws:// relays")
	relays := relayURLs(parse(fs, args), *plain)
	cl := c.client()
	ctx, cancel := c.ctx()
	defer cancel()
	t0 := time.Now()
	doc, err := cl.Info(ctx, relays[0])
	if err != nil {
		die(err)
	}
	var v any
	_ = json.Unmarshal(doc, &v)
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "NIP-11 from %s in %.1fs over the mixnet\n", relays[0].Host, time.Since(t0).Seconds())
}

// ---------------------------------------------------------------- probe

// DefaultProbe is a handful of widely used public relays.
var DefaultProbe = []string{"relay.damus.io", "nos.lol", "relay.primal.net", "nostr.wine", "relay.snort.social", "offchain.pub", "nostr.mom"}

type probeResult struct {
	Relay    string  `json:"relay"`
	OK       bool    `json:"ok"`
	ConnectS float64 `json:"connect_s"`
	FirstS   float64 `json:"first_event_s,omitempty"`
	EOSES    float64 `json:"eose_s,omitempty"`
	Events   int     `json:"events"`
	Invalid  int     `json:"invalid"`
	Error    string  `json:"error,omitempty"`
	Notice   string  `json:"notice,omitempty"`
}

func cmdProbe(args []string) {
	var c common
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	c.register(fs)
	par := fs.Int("parallel", 4, "relays probed at once")
	pos := parse(fs, args)
	if len(pos) == 0 {
		pos = DefaultProbe
	}
	relays := relayURLs(pos, false)
	cl := c.client()
	ctx, cancel := c.ctx()
	defer cancel()
	filter := json.RawMessage(`{"kinds":[1],"limit":3}`)
	res := make([]probeResult, len(relays))
	sem := make(chan struct{}, max(1, *par))
	var wg sync.WaitGroup
	for i, u := range relays {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := probeResult{Relay: u.Host}
			defer func() { res[i] = r }()
			pctx, pc := context.WithTimeout(ctx, 2*time.Minute)
			defer pc()
			t0 := time.Now()
			ws, err := cl.Dial(pctx, u)
			if err != nil {
				r.Error = err.Error()
				return
			}
			defer ws.Close(websocket.StatusNormalClosure, "")
			r.ConnectS = time.Since(t0).Seconds()
			t1 := time.Now()
			rr, err := nostr.Req(pctx, ws, "probe", []json.RawMessage{filter}, true, func(ev *nostr.Event, _ error) {
				if r.FirstS == 0 {
					r.FirstS = time.Since(t1).Seconds()
				}
			})
			r.Events, r.Invalid = rr.Events, rr.Invalid
			if len(rr.Notices) > 0 {
				r.Notice = rr.Notices[0]
			}
			if err != nil {
				r.Error = err.Error()
				return
			}
			if rr.EOSE {
				r.EOSES = time.Since(t1).Seconds()
			} else {
				r.Error = "CLOSED: " + rr.Closed
			}
			r.OK = rr.EOSE && rr.Events > 0
		}()
	}
	wg.Wait()
	sort.SliceStable(res, func(a, b int) bool { return res[a].OK && !res[b].OK })
	var sb strings.Builder
	tw := tabwriter.NewWriter(&sb, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "RELAY\tOK\tCONNECT\tEOSE\tEVENTS\tNOTE")
	nok := 0
	for _, r := range res {
		note := r.Error
		if note == "" {
			note = r.Notice
		}
		if r.OK {
			nok++
		}
		fmt.Fprintf(tw, "%s\t%v\t%s\t%s\t%d\t%s\n", r.Relay, r.OK, secs(r.ConnectS), secs(r.EOSES), r.Events, trunc(note, 90))
	}
	tw.Flush()
	c.out(res, strings.TrimRight(sb.String(), "\n")+fmt.Sprintf("\n%d of %d relays served signed events through the mixnet", nok, len(res)))
}

func secs(f float64) string {
	if f == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1fs", f)
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
