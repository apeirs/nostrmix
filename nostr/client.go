package nostr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// Dialer opens TCP streams (the mixnet dialer satisfies it).
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// ReadLimit for one relay message. Large kind-3 contact lists and long-form
// posts can be a few hundred kB; 16 MiB leaves room without being unbounded.
const ReadLimit = 16 << 20

// UserAgent is the only identifying header nostrmix sends to relays. It is the
// same for every user, so it does not single anyone out.
const UserAgent = "Mozilla/5.0"

// RelayURL normalises "nos.lol", "wss://nos.lol/", "nos.lol:8443/path" to a
// wss:// URL. Plain ws:// is refused unless allowPlain: the exit gateway would
// see the traffic in clear text.
func RelayURL(s string, allowPlain bool) (*url.URL, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "://") {
		s = "wss://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("bad relay %q: %w", s, err)
	}
	switch u.Scheme {
	case "wss", "https":
		u.Scheme = "wss"
	case "ws", "http":
		if !allowPlain {
			return nil, fmt.Errorf("refusing plain %s://: the Nym exit gateway would read it; use wss:// (or --allow-plain)", u.Scheme)
		}
		u.Scheme = "ws"
	default:
		return nil, fmt.Errorf("bad relay scheme %q", u.Scheme)
	}
	if u.Hostname() == "" || u.User != nil {
		return nil, fmt.Errorf("bad relay %q", s)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	u.Fragment = ""
	return u, nil
}

// Port returns the TCP port of a relay URL.
func Port(u *url.URL) int {
	if p := u.Port(); p != "" {
		n, _ := strconv.Atoi(p)
		return n
	}
	if u.Scheme == "ws" {
		return 80
	}
	return 443
}

// Client talks to relays through d.
type Client struct {
	D       Dialer
	RootCAs *x509.CertPool // nil = system roots (tests override)
	// Compress asks the relay for permessage-deflate (fewer Sphinx packets).
	Compress bool
}

func (c *Client) httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil, // never honour HTTP(S)_PROXY: the mixnet is the only path
			DialContext:         c.D.DialContext,
			TLSClientConfig:     &tls.Config{RootCAs: c.RootCAs},
			TLSHandshakeTimeout: 90 * time.Second,
			DisableKeepAlives:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Dial opens a WebSocket to the relay through the mixnet. TLS runs end to end
// between this process and the relay; the exit gateway relays ciphertext.
func (c *Client) Dial(ctx context.Context, u *url.URL) (*websocket.Conn, error) {
	h := http.Header{}
	h.Set("User-Agent", UserAgent)
	mode := websocket.CompressionDisabled
	if c.Compress {
		mode = websocket.CompressionNoContextTakeover
	}
	ws, resp, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPClient: c.httpClient(), HTTPHeader: h, CompressionMode: mode})
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("relay %s answered HTTP %d instead of a WebSocket upgrade (it may block Nym exit IPs): %w", u.Host, resp.StatusCode, err)
		}
		return nil, fmt.Errorf("relay %s over the mixnet: %w", u.Host, err)
	}
	ws.SetReadLimit(ReadLimit)
	return ws, nil
}

// Info fetches the NIP-11 relay information document through the mixnet.
func (c *Client) Info(ctx context.Context, u *url.URL) (json.RawMessage, error) {
	hu := *u
	hu.Scheme = map[string]string{"wss": "https", "ws": "http"}[u.Scheme]
	req, err := http.NewRequestWithContext(ctx, "GET", hu.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/nostr+json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("NIP-11 from %s over the mixnet: %w", u.Host, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NIP-11 from %s: HTTP %d", u.Host, resp.StatusCode)
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("NIP-11 from %s: not JSON (%d bytes)", u.Host, len(body))
	}
	return body, nil
}

// ReqResult summarises one subscription.
type ReqResult struct {
	Events  int      `json:"events"`
	Invalid int      `json:"invalid"`
	EOSE    bool     `json:"eose"`
	Closed  string   `json:"closed,omitempty"`
	Notices []string `json:"notices,omitempty"`
}

// Req sends ["REQ",sub,filters...] and calls onEvent for every event until
// EOSE, CLOSED or ctx ends. Invalid events (bad id/sig) are counted and passed
// with a non-nil error so the caller decides; verify=false skips the check.
func Req(ctx context.Context, ws *websocket.Conn, sub string, filters []json.RawMessage, verify bool, onEvent func(*Event, error)) (ReqResult, error) {
	var res ReqResult
	msg := []any{"REQ", sub}
	for _, f := range filters {
		msg = append(msg, f)
	}
	b, _ := json.Marshal(msg)
	if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
		return res, err
	}
	defer func() {
		b, _ := json.Marshal([]any{"CLOSE", sub})
		wctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = ws.Write(wctx, websocket.MessageText, b)
		cancel()
	}()
	for {
		_, data, err := ws.Read(ctx)
		if err != nil {
			return res, err
		}
		var arr []json.RawMessage
		if json.Unmarshal(data, &arr) != nil || len(arr) < 2 {
			continue
		}
		var typ, id string
		_ = json.Unmarshal(arr[0], &typ)
		switch typ {
		case "EVENT":
			if len(arr) < 3 || json.Unmarshal(arr[1], &id) != nil || id != sub {
				continue
			}
			ev, err := ParseEvent(arr[2])
			if err == nil && verify {
				err = ev.Check()
			}
			if err != nil {
				res.Invalid++
			} else {
				res.Events++
			}
			onEvent(ev, err)
		case "EOSE":
			if json.Unmarshal(arr[1], &id) == nil && id == sub {
				res.EOSE = true
				return res, nil
			}
		case "CLOSED":
			if json.Unmarshal(arr[1], &id) == nil && id == sub {
				res.Closed = "closed"
				if len(arr) > 2 {
					_ = json.Unmarshal(arr[2], &res.Closed)
				}
				return res, nil
			}
		case "NOTICE":
			var n string
			_ = json.Unmarshal(arr[1], &n)
			res.Notices = append(res.Notices, n)
		}
	}
}

// OK is a relay's answer to an EVENT (NIP-01 / NIP-20).
type OK struct {
	Relay    string  `json:"relay"`
	Accepted bool    `json:"accepted"`
	Message  string  `json:"message"`
	Error    string  `json:"error,omitempty"`
	Seconds  float64 `json:"seconds"`
}

// ErrNoOK means the relay closed or timed out without an OK for our event.
var ErrNoOK = errors.New("relay sent no OK for the event")

// Publish sends ["EVENT",ev] and waits for the matching ["OK",id,bool,msg].
func Publish(ctx context.Context, ws *websocket.Conn, ev *Event) (bool, string, error) {
	b, _ := json.Marshal([]any{"EVENT", ev})
	if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
		return false, "", err
	}
	for {
		_, data, err := ws.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return false, "", ErrNoOK
			}
			return false, "", err
		}
		var arr []json.RawMessage
		if json.Unmarshal(data, &arr) != nil || len(arr) < 3 {
			continue
		}
		var typ, id string
		_ = json.Unmarshal(arr[0], &typ)
		if typ != "OK" || json.Unmarshal(arr[1], &id) != nil || id != ev.ID {
			continue
		}
		var ok bool
		var msg string
		_ = json.Unmarshal(arr[2], &ok)
		if len(arr) > 3 {
			_ = json.Unmarshal(arr[3], &msg)
		}
		return ok, msg, nil
	}
}
