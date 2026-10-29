package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

// RESULT: red before opLocalNetworkDest — on a local box a name that resolves
// to a home network's address was put in the apply's allowlist.
func TestALocalBoxRefusesANameThatResolvesToAPrivateNetworkAtApply(t *testing.T) {
	localOpBox(t)
	prevOwn, prevRes := opActionOwnAddrs, opActionResolve
	opActionOwnAddrs = func() []net.IP { return nil }
	opActionResolve = func(_ context.Context, h string) ([]net.IP, error) {
		switch h {
		case "nas.home.example":
			return []net.IP{net.ParseIP("10.0.0.2")}, nil
		case "split.example.com":
			return []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("192.168.1.2")}, nil
		case "forge.example.com":
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		}
		return nil, fmt.Errorf("no")
	}
	t.Cleanup(func() { opActionOwnAddrs, opActionResolve = prevOwn, prevRes })

	for _, d := range []string{"nas.home.example:80", "split.example.com:443"} {
		if _, err := opResolveDests(context.Background(), []string{d}); err == nil ||
			!strings.Contains(err.Error(), "private network") {
			t.Errorf("%s: a local box resolves it into the allowlist: %v", d, err)
		}
	}
	got, err := opResolveDests(context.Background(), []string{"forge.example.com:443"})
	if err != nil || len(got.Addrs) != 1 || got.Addrs[0] != "203.0.113.10" {
		t.Fatalf("a public name resolves to its address: %+v %v", got, err)
	}

	// An anchored fleet keeps the same name.
	setupBox(t)
	if got, err := opResolveDests(context.Background(), []string{"nas.home.example:80"}); err != nil || got.Addrs[0] != "10.0.0.2" {
		t.Fatalf("an anchored box resolves a private control plane: %+v %v", got, err)
	}
}

// A destination written as an address is judged again at apply by the anchor
// the machine has then: an op held while the machine was anchored does not
// reach a private address after the anchor is gone.
func TestAPrivateDestinationHeldWhileAnchoredIsRefusedAtApplyOnceTheAnchorIsGone(t *testing.T) {
	setupBox(t)
	prevOwn := opActionOwnAddrs
	opActionOwnAddrs = func() []net.IP { return nil }
	t.Cleanup(func() { opActionOwnAddrs = prevOwn })
	for _, d := range []string{"10.0.0.2:80", "[::ffff:10.0.0.2]:80"} {
		if _, err := opResolveDests(context.Background(), []string{d}); err != nil {
			t.Fatalf("%s: an anchored box reaches its private control plane: %v", d, err)
		}
	}
	localOpBox(t)
	for _, d := range []string{"10.0.0.2:80", "[::ffff:10.0.0.2]:80"} {
		if _, err := opResolveDests(context.Background(), []string{d}); err == nil || !strings.Contains(err.Error(), "private network") {
			t.Errorf("%s: held while anchored, reached after the anchor is gone: %v", d, err)
		}
	}
}

// A verb fetches too: tree.checkout fetches its repo, and k8s.set_image
// fetches its repo to check ancestry, each with the bastion's own root and
// outside the program's sandbox. On a local machine that fetch is held to
// the rule a destination is: a repository whose host resolves to a private
// network is never fetched, and no git runs for it. An interpreter: none op
// is nothing but verbs, so this is the whole of its reach.
//
// RESULT: red before opFetchPin — the ancestry fetch ran git against the
// name, which git resolved itself, so a name on a home network was fetched.
func TestALocalBoxNeverFetchesAVerbsRepositoryFromAPrivateNetwork(t *testing.T) {
	localOpBox(t)
	prevOwn, prevRes := opActionOwnAddrs, opActionResolve
	opActionOwnAddrs = func() []net.IP { return nil }
	opActionResolve = func(_ context.Context, h string) ([]net.IP, error) {
		switch h {
		case "nas.home.example":
			return []net.IP{net.ParseIP("10.0.0.2")}, nil
		case "split.example.com":
			return []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("::ffff:192.168.1.2")}, nil
		case "meta.example.com":
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		}
		return nil, fmt.Errorf("no")
	}
	t.Cleanup(func() { opActionOwnAddrs, opActionResolve = prevOwn, prevRes })

	older, newer := strings.Repeat("a", 40), strings.Repeat("b", 40)
	for repo, want := range map[string]string{
		"https://nas.home.example/acme/app.git":  "private network",
		"https://split.example.com/acme/app.git": "private network",
		"https://meta.example.com/acme/app.git":  "link-local",
	} {
		err := opAncestryByFetch(repo, older, newer, nil)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: a local box fetched it: %v", repo, err)
		}
	}
	// The pin a public repository is fetched under: git is held to the
	// address checked here and never looks the name up again.
	prevGit := opGitPinnable
	opGitPinnable = func() string { return "" }
	t.Cleanup(func() { opGitPinnable = prevGit })
	opActionResolve = func(_ context.Context, h string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("2001:db8::10")}, nil
	}
	if pin, err := opFetchPin(context.Background(), "https://forge.example.com:8443/acme/app.git"); err != nil ||
		strings.Join(pin, " ") != "-c http.curloptResolve=forge.example.com:8443:[2001:db8::10]" {
		t.Fatalf("a public repository is fetched pinned to its address: %q %v", pin, err)
	}
	// A git that would drop the pin is refused, never run unpinned.
	opGitPinnable = func() string { return "git 2.34 cannot hold a fetch to one address" }
	if _, err := opFetchPin(context.Background(), "https://forge.example.com/acme/app.git"); err == nil {
		t.Fatal("a git that ignores the pin fetched unpinned")
	}
	// An anchored fleet fetches from its private forge, pinned to it.
	opGitPinnable = func() string { return "" }
	setupBox(t)
	opActionResolve = func(_ context.Context, h string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.2")}, nil
	}
	if pin, err := opFetchPin(context.Background(), "https://nas.home.example/acme/app.git"); err != nil ||
		strings.Join(pin, " ") != "-c http.curloptResolve=nas.home.example:443:10.0.0.2" {
		t.Fatalf("an anchored box fetches from its private forge: %q %v", pin, err)
	}
}

// An anchored machine keeps its fleet's private forges, but a verb's fetch
// there is still never this machine, its loopback, a link-local address or a
// cloud's metadata service: a name steered to one is refused before git runs.
//
// RESULT: red before opFetchPin ran on anchored machines — git fetched each
// name itself, whatever it resolved to.
func TestAnAnchoredBoxNeverFetchesAVerbsRepositoryFromItselfOrTheMetadataService(t *testing.T) {
	setupBox(t)
	prevOwn, prevRes := opActionOwnAddrs, opActionResolve
	opActionOwnAddrs = func() []net.IP { return []net.IP{net.ParseIP("203.0.113.99")} }
	opActionResolve = func(_ context.Context, h string) ([]net.IP, error) {
		switch h {
		case "lo.example.com":
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		case "mapped.example.com":
			return []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("::ffff:127.0.0.1")}, nil
		case "meta.example.com":
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		case "ali.example.com":
			return []net.IP{net.ParseIP("100.100.100.200")}, nil
		case "self.example.com":
			return []net.IP{net.ParseIP("203.0.113.99")}, nil
		}
		return nil, fmt.Errorf("no")
	}
	t.Cleanup(func() { opActionOwnAddrs, opActionResolve = prevOwn, prevRes })
	older, newer := strings.Repeat("a", 40), strings.Repeat("b", 40)
	for repo, want := range map[string]string{
		"https://lo.example.com/acme/app.git":     "loopback",
		"https://mapped.example.com/acme/app.git": "loopback",
		"https://meta.example.com/acme/app.git":   "link-local",
		"https://ali.example.com/acme/app.git":    "metadata service",
		"https://self.example.com/acme/app.git":   "this machine",
	} {
		err := opAncestryByFetch(repo, older, newer, nil)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: an anchored box fetched it: %v", repo, err)
		}
	}
}

// k8s.set_image hands an image to the cluster, and the machine's container
// runtime pulls it by name, outside the bastion's walls. On a local machine
// an image whose registry is on the private network around it is refused
// where the bastion takes the image, so the runtime is never sent there; a
// Docker Hub repository and a public registry pass; an anchored fleet keeps
// its private registry.
//
// RESULT: red before opRegistryOK — the plan took a receipt for an image on a
// home network's registry and went on to the live image's record.
func TestALocalBoxNeverPutsLiveAnImageFromARegistryOnItsNetwork(t *testing.T) {
	localOpBox(t)
	prevOwn, prevRes := opActionOwnAddrs, opActionResolve
	opActionOwnAddrs = func() []net.IP { return nil }
	opActionResolve = func(_ context.Context, h string) ([]net.IP, error) {
		switch h {
		case "nas.home.example":
			return []net.IP{net.ParseIP("10.0.0.2")}, nil
		case "registry.example.com":
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		}
		return nil, fmt.Errorf("no")
	}
	t.Cleanup(func() { opActionOwnAddrs, opActionResolve = prevOwn, prevRes })
	useAncestry(t, func(_, _, _ string, _ []string) error { return nil })
	ctx := context.Background()
	commit := strings.Repeat("c", 40)
	for i, tc := range []struct{ image, want string }{
		{"nas.home.example:5000/acme/web", "private network"},
		{"10.0.0.2:5000/acme/web", "private network"},
		{"192.168.1.2/acme/web", "private network"},
		{"localhost:5000/acme/web", "loopback"},
		{"169.254.169.254/acme/web", "link-local"},
		{"registry.example.com/acme/web", ""},
		{"acme/web", ""},
	} {
		digest := "sha256:" + strings.Repeat(fmt.Sprintf("%x", i+1), 64)
		if _, err := opIssueReceipts("r", "web-build", strings.Repeat("e", 64), "{}", []opResultImage{{Image: tc.image,
			Digest: digest, Source: tRepo, Commit: commit}}); err != nil {
			t.Fatal(err)
		}
		f := &fakeKube{containers: map[string]string{"bridge": tc.image + "@sha256:" + strings.Repeat("0", 64)}}
		useFakeKube(t, f)
		line := setImageLine(digest)
		line.Args["image"] = tc.image
		_, err := opImagePlan(ctx, line, nil)
		if tc.want != "" {
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "comes from the registry") {
				t.Errorf("%s: a local box would put it live: %v", tc.image, err)
			}
			if _, err := opImageDo(ctx, line, nil, nil, ""); err == nil || len(f.sets()) != 0 {
				t.Errorf("%s: and set it: %v %v", tc.image, err, f.sets())
			}
		} else if err != nil && strings.Contains(err.Error(), "comes from the registry") {
			t.Errorf("%s: a public registry is refused: %v", tc.image, err)
		}
	}
	// An anchored fleet keeps its private registry.
	setupBox(t)
	if err := opRegistryOK(ctx, "nas.home.example:5000/acme/web@sha256:"+strings.Repeat("1", 64)); err != nil {
		t.Fatalf("an anchored box pulls from its private registry: %v", err)
	}
}
