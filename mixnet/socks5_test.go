package mixnet

import "testing"

func TestEncodeAddrAndParse(t *testing.T) {
	if b, _ := EncodeAddr("nos.lol"); b[0] != 3 || b[1] != 7 || string(b[2:]) != "nos.lol" {
		t.Fatalf("domain: %v", b)
	}
	if b, _ := EncodeAddr("1.2.3.4"); len(b) != 5 || b[0] != 1 {
		t.Fatalf("ipv4: %v", b)
	}
	if b, _ := EncodeAddr("::1"); len(b) != 17 || b[0] != 4 {
		t.Fatalf("ipv6: %v", b)
	}
	if p, _ := ParseProxy("socks5h://127.0.0.1"); p != "127.0.0.1:1080" {
		t.Fatal(p)
	}
	for in, want := range map[string]string{"nos.lol": "nos.lol:443", "https://relay.damus.io": "relay.damus.io:443", "x.org:8443": "x.org:8443"} {
		if got, err := HostPort(in, 443); err != nil || got != want {
			t.Fatalf("HostPort(%q) = %q %v", in, got, err)
		}
	}
}
