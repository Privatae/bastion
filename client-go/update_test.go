package main

import "testing"

func TestParseUpdateTarget(t *testing.T) {
	cases := []struct {
		body string
		want string
	}{
		{`{"token_id":43,"ok":true,"update":{"version":"0.9.3"}}`, "0.9.3"},
		{`{"token_id":43,"ok":true}`, ""}, // no directive
		{`{"update":null}`, ""},           // explicit null
		{`{"update":{"version":""}}`, ""}, // empty version
		{`not json`, ""},                  // garbage
	}
	for _, c := range cases {
		if got := parseUpdateTarget([]byte(c.body)); got != c.want {
			t.Errorf("parseUpdateTarget(%q) = %q, want %q", c.body, got, c.want)
		}
	}
}
