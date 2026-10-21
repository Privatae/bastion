package main

import "testing"

func TestValidHostName(t *testing.T) {
	good := []string{"entity-9001.host.example", "entity-9002.host.example", "a.b.c"}
	for _, h := range good {
		if !validHostName(h) {
			t.Errorf("validHostName(%q) = false, want true", h)
		}
	}
	// Traversal / clobber attempts a hostile redeem response could send.
	bad := []string{
		"", "../../evil", "pairings/../pairings/entity-9001.host.example",
		"a/b", "..", ".hidden", "trailing.", "has space", "semi;colon",
	}
	for _, h := range bad {
		if validHostName(h) {
			t.Errorf("validHostName(%q) = true, want false (unsafe)", h)
		}
	}
}
