package main

import (
	"testing"
	"time"
)

func TestBuildFilter(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	f, err := buildFilter("1,30023", "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg", "", 5, "24h", "", "t=nym,t=privacy", "", now)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"#t":["nym","privacy"],"authors":["7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"],"kinds":[1,30023],"limit":5,"since":1799913600}`
	if string(f) != want {
		t.Fatalf("got  %s\nwant %s", f, want)
	}
	for _, bad := range [][]string{{"x", "", ""}, {"", "nsec1abc", ""}, {"", "", "tag"}} {
		if _, err := buildFilter(bad[0], bad[1], "", 0, "", "", bad[2], "", now); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	if ts, _ := parseTime("7d", now); ts != 1_800_000_000-7*86400 {
		t.Fatal(ts)
	}
	if ts, _ := parseTime("1700000000", now); ts != 1700000000 {
		t.Fatal(ts)
	}
	if _, err := parseTime("yesterday", now); err == nil {
		t.Fatal("bad time accepted")
	}
}
