package main

// backupcli.go — `privatae-bastion backup ...`, the person's commands for
// their own backups. Every one of them works with no host and no network:
// a backup file, the key held here (or a key file the person names), and a
// folder to write to are all they need.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
)

const backupUsage = `usage:
  privatae-bastion backup key init [--replace] [--label <name>]
      make this bastion's backup key here and print what to register on your
      host (Settings > Backup > keys: kind, label, public key). --replace makes
      a new one and keeps the old one, which still opens the backups made with it
  privatae-bastion backup key show
      the key this bastion holds, its fingerprint, and any older keys it keeps
  privatae-bastion backup reseal --sidecar <file> --to <host key> [--stamp <stamp>]
                                 [--out <file>] [--identity <key file>]
      seal one backup's key to a host's own key (age1... or base64), so that
      host, and only it, can open that one backup
  privatae-bastion backup requests [--host <host>]
      restore requests your host sent this machine
  privatae-bastion backup approve [--host <host>] <id> | deny [--host <host>] <id>
      answer one
  privatae-bastion backup restore-plan --dir <folder> [--stamp <stamp> --to <new host key>]
      restoring a lost host: list the backups in a folder, and reseal the one
      you choose to the key of the host that replaces it
  privatae-bastion backup share --with <host> (--from <host> | --dir <folder>)
      let the host paired as <host> list and send the backups in another
      host's backup folder here (or any folder) — how a host that replaces a
      lost one reaches the copies the lost one kept on this machine
  privatae-bastion backup shares --with <host> / unshare --with <host> <name>
      the folders shared with a host, and taking one back`

func cmdBackup(args []string) error {
	if len(args) == 0 {
		return errors.New(backupUsage)
	}
	switch args[0] {
	case "key":
		if len(args) >= 2 && args[1] == "init" {
			replace := false
			var a []string
			for _, x := range args[2:] {
				if x == "--replace" {
					replace = true
					continue
				}
				a = append(a, x)
			}
			flags, rest := backupFlags(a, "--label")
			if len(rest) != 0 {
				return errors.New(backupUsage)
			}
			return cmdBackupKeyInit(replace, flags["--label"])
		}
		if len(args) >= 2 && args[1] == "show" {
			return cmdBackupKeyShow()
		}
	case "reseal":
		flags, rest := backupFlags(args[1:], "--sidecar", "--to", "--stamp", "--out", "--identity")
		if len(rest) != 0 || flags["--sidecar"] == "" || flags["--to"] == "" {
			return errors.New(backupUsage)
		}
		return cmdBackupReseal(flags["--sidecar"], flags["--to"], flags["--stamp"], flags["--out"], flags["--identity"])
	case "requests":
		host, rest := takeHostFlag(args[1:])
		if len(rest) != 0 {
			return errors.New(backupUsage)
		}
		return cmdBackupRequests(host)
	case "approve", "deny":
		host, rest := takeHostFlag(args[1:])
		if len(rest) != 1 {
			return errors.New(backupUsage)
		}
		return cmdBackupDecide(host, rest[0], args[0] == "approve")
	case "share":
		flags, rest := backupFlags(args[1:], "--with", "--from", "--dir")
		if len(rest) != 0 || flags["--with"] == "" || (flags["--from"] == "") == (flags["--dir"] == "") {
			return errors.New(backupUsage)
		}
		return cmdBackupShare(flags["--with"], flags["--from"], flags["--dir"])
	case "shares":
		flags, rest := backupFlags(args[1:], "--with")
		if len(rest) != 0 || flags["--with"] == "" {
			return errors.New(backupUsage)
		}
		return cmdBackupShares(flags["--with"])
	case "unshare":
		flags, rest := backupFlags(args[1:], "--with")
		if len(rest) != 1 || flags["--with"] == "" {
			return errors.New(backupUsage)
		}
		return cmdBackupUnshare(flags["--with"], rest[0])
	case "restore-plan":
		flags, rest := backupFlags(args[1:], "--dir", "--stamp", "--to", "--out", "--identity")
		if len(rest) != 0 || flags["--dir"] == "" {
			return errors.New(backupUsage)
		}
		return cmdBackupRestorePlan(flags)
	}
	return errors.New(backupUsage)
}

// backupFlags splits `--name value` pairs (only the names given) from the
// positional arguments.
func backupFlags(args []string, names ...string) (map[string]string, []string) {
	known := map[string]bool{}
	for _, n := range names {
		known[n] = true
	}
	out := map[string]string{}
	var rest []string
	for i := 0; i < len(args); i++ {
		if known[args[i]] && i+1 < len(args) {
			out[args[i]] = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	return out, rest
}

func cmdBackupKeyInit(replace bool, label string) error {
	if label == "" {
		label, _ = os.Hostname()
	}
	if len(label) > 120 || strings.ContainsAny(label, "\n\r\t\x00") {
		return errors.New("--label must be one short line")
	}
	k, err := backupKeyInit(replace)
	if err != nil {
		return err
	}
	reg, _ := json.Marshal(map[string]string{"kind": "bastion", "label": label, "pubkey_b64": k.PubB64})
	fmt.Println("This bastion's backup key is made and kept here only:", k.Path)
	fmt.Println()
	fmt.Println("  fingerprint:  ", k.Fingerprint)
	fmt.Println("  age recipient:", k.Recipient)
	fmt.Println()
	fmt.Println("Register it on your host (Settings > Backup > keys) with these three fields:")
	fmt.Println("  kind:       bastion")
	fmt.Println("  label:     ", label)
	fmt.Println("  public key:", k.PubB64)
	fmt.Println("  (as JSON:", string(reg)+")")
	fmt.Println()
	fmt.Println("From the host's next backup on, this key opens your backups, and this bastion can")
	fmt.Println("hand a restoring host the key to one of them. Keep a copy of the key file")
	fmt.Println("somewhere safe: without it (or another key you registered), those backups")
	fmt.Println("cannot be opened.")
	return nil
}

func cmdBackupKeyShow() error {
	active, all, err := backupKeysLoad()
	if err != nil {
		return err
	}
	if len(all) == 0 {
		fmt.Println("no backup key on this machine — make one with `privatae-bastion backup key init`")
		return nil
	}
	for _, k := range all {
		state := "older key (still opens the backups made with it)"
		if active != nil && k.Fingerprint == active.Fingerprint {
			state = "current key"
		}
		fmt.Printf("%s  %s\n  public key:    %s\n  age recipient: %s\n  made:          %s\n  key file:      %s\n\n",
			k.Fingerprint, state, k.PubB64, k.Recipient, k.CreatedAt, k.Path)
	}
	return nil
}

func backupIDs(identityFile string) ([]age.Identity, error) {
	if identityFile != "" {
		return identitiesFromFile(identityFile)
	}
	return backupIdentities()
}

func cmdBackupReseal(sidecarFile, to, stamp, out, identityFile string) error {
	ids, err := backupIDs(identityFile)
	if err != nil {
		return err
	}
	r, err := parseBackupRecipient(to)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(sidecarFile)
	if err != nil {
		return err
	}
	sealed, sc, err := resealSidecar(raw, ids, r, stamp)
	if err != nil {
		return err
	}
	if out == "" {
		pub, _ := recipientRaw(r)
		out = sc.Stamp + ".key.resealed-" + backupKeyFingerprint(pub) + ".age"
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("cannot write %s: %w", out, err)
	}
	if _, err := f.Write(sealed); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("the key to the backup of %s is sealed to %s in %s\n", sc.Stamp, r.String(), out)
	return nil
}

// ── restoring a lost host ───────────────────────────────────────────────────

type backupListing struct {
	Stamp   string `json:"stamp"`
	Data    string `json:"data,omitempty"`
	Bytes   int64  `json:"bytes"`
	Sidecar string `json:"sidecar,omitempty"`
}

func listBackupDir(dir string) ([]backupListing, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	m := map[string]*backupListing{}
	for _, e := range entries {
		mm := backupFileRe.FindStringSubmatch(e.Name())
		if mm == nil || !e.Type().IsRegular() {
			continue
		}
		l := m[mm[1]]
		if l == nil {
			l = &backupListing{Stamp: mm[1]}
			m[mm[1]] = l
		}
		p := filepath.Join(dir, e.Name())
		if mm[2] == "tar.zst.age" {
			fi, _ := e.Info()
			l.Data = p
			if fi != nil {
				l.Bytes = fi.Size()
			}
		} else {
			l.Sidecar = p
		}
	}
	var out []backupListing
	for _, l := range m {
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Stamp > out[j].Stamp })
	return out, nil
}

func cmdBackupRestorePlan(flags map[string]string) error {
	list, err := listBackupDir(flags["--dir"])
	if err != nil {
		return err
	}
	if flags["--stamp"] == "" {
		if len(list) == 0 {
			fmt.Println("no backups in", flags["--dir"])
			return nil
		}
		fmt.Println("backups in", flags["--dir"], "(newest first):")
		for _, l := range list {
			note := ""
			switch {
			case l.Data == "":
				note = "  (sidecar only — the backup file itself is not here)"
			case l.Sidecar == "":
				note = "  (no sidecar here, so it cannot be resealed)"
			}
			fmt.Printf("  %s  %d bytes%s\n", l.Stamp, l.Bytes, note)
		}
		fmt.Println()
		fmt.Println("To restore one onto the host that replaces a lost one, run again with")
		fmt.Println("  --stamp <stamp> --to <the new host's key, from its Settings > Backup > Restore>")
		return nil
	}
	if flags["--to"] == "" {
		return errors.New("say which host the backup is for: --to <the new host's key>")
	}
	var pick *backupListing
	for i := range list {
		if list[i].Stamp == flags["--stamp"] {
			pick = &list[i]
		}
	}
	if pick == nil || pick.Sidecar == "" {
		return fmt.Errorf("no backup of %s with a sidecar in %s", flags["--stamp"], flags["--dir"])
	}
	out := flags["--out"]
	if err := cmdBackupReseal(pick.Sidecar, flags["--to"], pick.Stamp, out, flags["--identity"]); err != nil {
		return err
	}
	fmt.Println()
	fmt.Println("Next, on the new host: Settings > Backup > Restore > use a resealed key, and give it")
	fmt.Println("that file. The new host then needs the backup file of", pick.Stamp+":")
	fmt.Println("  - in platform storage or your own S3 bucket, a new host finds it only if it has the")
	fmt.Println("    same host number as the lost one;")
	if pick.Data != "" {
		fmt.Println("  - from this machine: pair this bastion with the new host, and share this folder")
		fmt.Println("    with it (privatae-bastion backup share --with <new host> --dir <this folder>);")
		fmt.Println("    the new host then lists it and asks this bastion to send it.")
	}
	fmt.Println()
	fmt.Println("The host that restores it has to exist first. Running one on hardware you own needs")
	fmt.Println("infrastructure this bastion does not provide: see \"Restoring a lost host\" in the README.")
	return nil
}

// ── sharing a folder with another pairing ───────────────────────────────────

func pairingByName(name string) (*Config, error) {
	cfgs, err := loadPairings()
	if err != nil {
		return nil, err
	}
	cfg, err := findPairing(cfgs, name)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("no pairing matches '%s' — paired hosts:\n  %s", name, strings.Join(hostNames(cfgs), "\n  "))
	}
	return cfg, nil
}

func cmdBackupShare(with, from, dir string) error {
	reader, err := pairingByName(with)
	if err != nil {
		return err
	}
	root := reader.backupRoot()
	if root == "" {
		return fmt.Errorf("%s has no backup folder on this machine", reader.HostName)
	}
	label := dir
	if from != "" {
		src, err := pairingByName(from)
		if err != nil {
			return err
		}
		if dir = src.backupRoot(); dir == "" {
			return fmt.Errorf("%s has no backup folder on this machine", src.HostName)
		}
		label = src.HostName
	} else {
		label = filepath.Base(filepath.Clean(dir))
	}
	if why := backupRootProblem(reader.HostName, root); why != "" {
		return errors.New(why)
	}
	s, err := addBackupShare(reader.HostName, root, dir, label)
	if err != nil {
		return err
	}
	fmt.Printf("%s can now list the backups in %s as shared/%s, and ask this bastion to send\n", reader.HostName, s.Dir, s.Slug)
	fmt.Printf("them to it. It cannot write there. Take it back with: privatae-bastion backup unshare --with %s %s\n", with, s.Slug)
	return nil
}

func cmdBackupShares(with string) error {
	reader, err := pairingByName(with)
	if err != nil {
		return err
	}
	list := sharesFor(reader.HostName)
	if len(list) == 0 {
		fmt.Println("no folders are shared with", reader.HostName)
		return nil
	}
	for _, s := range list {
		fmt.Printf("shared/%s  %s  (shared %s)\n", s.Slug, s.Dir, s.Added)
	}
	return nil
}

func cmdBackupUnshare(with, slug string) error {
	reader, err := pairingByName(with)
	if err != nil {
		return err
	}
	if err := dropBackupShare(reader.HostName, strings.TrimPrefix(slug, "shared/")); err != nil {
		return err
	}
	fmt.Println("taken back:", reader.HostName, "can no longer list or send the backups in shared/"+strings.TrimPrefix(slug, "shared/"))
	return nil
}
