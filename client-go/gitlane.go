package main

// Git lane: Gitea through the Host.
//
// This bastion offers a loopback HTTP proxy for the user's LOCAL git to reach
// git.privatae.ai through their host; every local connection is spliced over the
// tunnel into ONE WebSocket on the host (/bastion-git, same bearer + mTLS binding
// as the other lanes) and the host relays it on to the forge. Which addresses the
// forge itself answers is the forge's rule; nothing here sets or checks it. The
// wire framing is the egress lane's ('D'+bytes / 'E' end) with the roles swapped,
// so wsConn is reused unchanged.
//
// Setup for the user (printed by `privatae-bastion git-setup`):
//   git config --global http.https://git.privatae.ai.proxy http://127.0.0.1:<port>
//   git config --global credential.https://git.privatae.ai.helper "!privatae-bastion git-credential"
// The credential helper asks the host for the user's platform-minted token on every
// git auth. git-setup clears the per-URL helper chain first, and the helper hands
// the token back in a form git's own store and cache helpers do not keep
// (cmdGitCredential; a helper that records everything still receives it).

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// gitForgeHost is the one forge this lane serves. The credential helper
// answers only for this host, and the tests name it through this constant.
const gitForgeHost = "git.privatae.ai"

// runGitLane serves the loopback git proxy: one host WebSocket per local connection.
func runGitLane(ln net.Listener, wsURL string, tlsCfg *tls.Config,
	dialHost func(ctx context.Context) (net.Conn, error), bearer string) {
	dialer := &websocket.Dialer{
		NetDialContext:   func(ctx context.Context, network, addr string) (net.Conn, error) { return dialHost(ctx) },
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 20 * time.Second,
	}
	for {
		local, err := ln.Accept()
		if err != nil {
			return
		}
		go func(local net.Conn) {
			defer local.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			ws, _, err := dialer.DialContext(ctx, wsURL, http.Header{})
			cancel()
			if err != nil {
				_, _ = io.WriteString(local, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\nprivatae-bastion: host unreachable over the tunnel\r\n")
				return
			}
			if err := ws.WriteMessage(websocket.TextMessage, []byte("BEARER "+bearer)); err != nil {
				_ = ws.Close()
				return
			}
			stopKA := armWSKeepalive(ws)
			defer stopKA()
			hc := &wsConn{ws: ws}
			defer hc.Close()
			spliceHalfClose(local, hc)
		}(local)
	}
}

// spliceHalfClose copies both directions and half-closes each side when the other ends.
func spliceHalfClose(a net.Conn, b *wsConn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		_ = b.CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// cmdGitCredential implements the git credential-helper protocol (`get` only): the
// host answers with the user's platform-minted token for git.privatae.ai. Other
// actions (store/erase) are no-ops — nothing is ever stored here.
//
// Nothing ELSE should store it either, and git-setup's helper-chain reset
// cannot promise that alone: git hands an approved credential to every helper
// in its list, and a helper configured after the reset (later in the same
// file, or in a repository's own config) is in that list. So when git says it
// understands the authtype capability, the token goes back as a pre-encoded
// Basic credential marked ephemeral, with no password field. git builds the
// same Authorization header from it, and git's own store and cache helpers
// keep nothing, because they store only a username and password. A helper
// that records everything it is given still receives the token: git passes
// the credential field on store to every helper. quit stops git asking any
// later helper for the forge's credential. A git too old to announce the
// capability gets the username and password form, and for it the reset is the
// only protection.
func cmdGitCredential(host string, action string) error {
	if action != "get" {
		return nil
	}
	in := map[string]string{}
	authtype := false
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		if line == "capability[]=authtype" {
			authtype = true
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			in[k] = v
		}
	}
	if h := in["host"]; h != "" && !strings.EqualFold(h, gitForgeHost) {
		return nil // not ours; git falls through to its next helper
	}
	cfgs, err := loadPairings()
	if err != nil {
		return err
	}
	var cfg *Config
	switch {
	case host != "":
		cfg, err = findPairing(cfgs, host)
		if err != nil {
			return err
		}
		if cfg == nil {
			return fmt.Errorf("no pairing matches --host '%s'", host)
		}
	case len(cfgs) == 1:
		cfg = cfgs[0]
	case len(cfgs) == 0:
		return fmt.Errorf("not paired yet — run `privatae-bastion pair <token>` first")
	default:
		return fmt.Errorf("%d hosts are paired — configure the helper with --host: "+
			"credential.https://git.privatae.ai.helper \"!privatae-bastion git-credential --host <host>\"", len(cfgs))
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+cfg.ListenAddr+"/git-credential", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.OperatorSecret)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("the bastion daemon isn't running — start it with `privatae-bastion run` (%w)", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("host refused (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	_, err = os.Stdout.Write(gitCredentialReply(body, authtype))
	return err
}

// gitCredentialReply turns the host's "username=…\npassword=…\n" into what this
// helper tells git (see cmdGitCredential for why the two forms). An answer
// without both fields is passed on as it came, as before: git then asks its
// next helper or the user, which is its own behaviour for a helper with nothing.
func gitCredentialReply(body []byte, authtype bool) []byte {
	var user, pass string
	var haveUser, havePass bool
	for _, line := range strings.Split(string(body), "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), "=")
		switch {
		case !ok:
		case k == "username":
			user, haveUser = v, true
		case k == "password":
			pass, havePass = v, true
		}
	}
	if !haveUser || !havePass {
		return body
	}
	if authtype {
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		return []byte("capability[]=authtype\nauthtype=Basic\ncredential=" + cred + "\nephemeral=1\nquit=1\n")
	}
	return []byte("username=" + user + "\npassword=" + pass + "\nquit=1\n")
}

// cmdGitSetup prints the three git config lines for every pairing: the proxy,
// the reset of the forge's helper chain, and the helper.
func cmdGitSetup() error {
	all, err := loadPairings()
	if err != nil {
		return err
	}
	if len(all) == 0 {
		return fmt.Errorf("no pairings — run `privatae-bastion pair <token>` first")
	}
	fmt.Println("git to git.privatae.ai through this bastion and your host:")
	if len(all) > 1 {
		fmt.Println("(several hosts are paired: pick ONE for git, and name it with --host in the helper line)")
	}
	for _, c := range all {
		addr := c.GitProxyAddr
		if addr == "" {
			addr = nextGitProxyAddr(all) + " (allocated on the next `privatae-bastion run`)"
		}
		fmt.Printf("\n  %s\n", c.HostName)
		fmt.Printf("    git config --global http.https://git.privatae.ai.proxy http://%s\n", addr)
		if len(all) > 1 {
			fmt.Printf("    git config --global --replace-all credential.https://git.privatae.ai.helper \"\"\n")
			fmt.Printf("    git config --global --add credential.https://git.privatae.ai.helper \"!privatae-bastion git-credential --host %s\"\n", c.HostName)
		}
	}
	if len(all) == 1 {
		// The empty helper FIRST resets the chain for this URL, so a global `store`
		// helper never caches the token this one returns.
		fmt.Printf("    git config --global --replace-all credential.https://git.privatae.ai.helper \"\"\n")
		fmt.Printf("    git config --global --add credential.https://git.privatae.ai.helper \"!privatae-bastion git-credential\"\n")
	}
	fmt.Println("\nThen `privatae-bastion run` must be running whenever you use git.")
	return nil
}
