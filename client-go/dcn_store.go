package main

// dcn_store.go — every byte a machine-store op touches is reached through ONE
// handle on the folder the person granted.
//
// WHY. The bastion is often root (a networked install, the macOS and Windows
// system service), and the granted folder is often someone else's. Checking a
// path and then opening it by name leaves two ways out of the store for
// whoever can write in it or above it:
//
//   - the granted folder itself turned into a link to another folder after the
//     grant. The old check resolved the root again on every op and judged the
//     path against wherever it led NOW, so no race was needed;
//   - a file or folder inside the store swapped for a link between the check
//     and the open (or the rename, for a move plan).
//
// So: the folder's real path is PINNED at grant sync (rec.RootReal, this box's
// own field, outside the signed bytes), an op whose root now leads elsewhere
// is refused, and the op opens the pinned folder as an os.Root, which never
// follows a link out of it, whatever happens to the names afterwards. That
// handle is then checked to be the folder at the pinned path reached with no
// link at all (dcnNoLinkStat: an open that refuses a link in every component
// on Linux and macOS), so a swap of a folder above the store between the two
// opens is refused too.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

// errDcnRepointed is the refusal for a granted folder that leads elsewhere now.
var errDcnRepointed = errors.New("the granted folder now leads somewhere other than the folder that was granted; " +
	"a new grant for it is the repair")

// dcnRealRoot is where the grant's root leads now: its links resolved.
func dcnRealRoot(root string) (string, error) {
	real, err := filepath.EvalSymlinks(filepath.Clean(root))
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(real) {
		return "", errors.New("the granted folder is not an absolute path")
	}
	return filepath.Clean(real), nil
}

// dcnPinFor is the real root a sync records: the one already pinned for the
// same root while the store is held (a re-sync, a renewed grant), else where
// the root leads now ("" when it cannot be resolved yet; pinned at first use).
func dcnPinFor(prev *dcnGrantRec, prevRoot, root string) string {
	if prev != nil && prev.RootReal != "" && filepath.Clean(prevRoot) == filepath.Clean(root) {
		return prev.RootReal
	}
	real, err := dcnRealRoot(root)
	if err != nil {
		return ""
	}
	return real
}

// dcnStorePin is the pinned real root of a held store, pinning it now (and
// saving it) for a grant synced before pins existed.
func dcnStorePin(dir string, storeID int64, root string) (string, error) {
	grantsMu.Lock()
	defer grantsMu.Unlock()
	f, err := dcnLoadFile(dir)
	if err != nil {
		return "", err
	}
	key := strconv.FormatInt(storeID, 10)
	rec, ok := f.Stores[key]
	if !ok {
		return "", errors.New("no grant for this store on this box")
	}
	if rec.RootReal != "" {
		return rec.RootReal, nil
	}
	real, err := dcnRealRoot(root)
	if err != nil {
		return "", err
	}
	rec.RootReal = real
	f.Stores[key] = rec
	if err := dcnSaveFile(dir, f); err != nil {
		return "", err
	}
	return real, nil
}

// dcnOpenStore opens the store a verified grant names, as the folder that was
// granted, or refuses.
func dcnOpenStore(dir string, storeID int64, terms *dcnTerms) (*os.Root, error) {
	pin, err := dcnStorePin(dir, storeID, terms.Root)
	if err != nil {
		return nil, fmt.Errorf("the granted folder cannot be opened: %w", err)
	}
	real, err := dcnRealRoot(terms.Root)
	if err != nil {
		return nil, fmt.Errorf("the granted folder cannot be opened: %w", err)
	}
	if real != pin {
		return nil, errDcnRepointed
	}
	return dcnOpenRootAt(pin)
}

// dcnOpenRootAt opens real (a resolved, absolute path) as an os.Root and
// checks that the handle is the folder reached at real with no link in any
// component, so nothing above the folder was swapped while it was opened.
func dcnOpenRootAt(real string) (*os.Root, error) {
	r, err := os.OpenRoot(real)
	if err != nil {
		return nil, fmt.Errorf("the granted folder cannot be opened: %w", err)
	}
	rfi, err := r.Stat(".")
	if err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("the granted folder cannot be opened: %w", err)
	}
	nfi, err := dcnNoLinkStat(real)
	if err != nil || !nfi.IsDir() || !os.SameFile(rfi, nfi) {
		_ = r.Close()
		return nil, errDcnRepointed
	}
	return r, nil
}

// dcnRel is a path the sandbox accepted (cleanRel/dcnResolvePath's joined
// form) as a name inside the root handle.
func dcnRel(root, joined string) (string, error) {
	rel, err := filepath.Rel(filepath.Clean(root), joined)
	if err != nil || rel == ".." || filepath.IsAbs(rel) || len(rel) >= 3 && rel[:3] == ".."+string(os.PathSeparator) {
		return "", errors.New("path escapes the store root")
	}
	return rel, nil
}

// dcnEscaped: the root handle refused a name because it leads out of the store.
func dcnEscaped(err error) bool {
	var pe *os.PathError
	return errors.As(err, &pe) && pe.Err != nil && pe.Err.Error() == "path escapes from parent"
}

// dcnRootAtomicWrite is atomicWrite inside the store's handle: folders 0700,
// the file 0600, written beside its name and renamed into place.
func dcnRootAtomicWrite(r *os.Root, rel string, data []byte) error {
	if d := filepath.Dir(rel); d != "." {
		if err := r.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	// The side name is unguessable and opened O_EXCL, as atomicWrite's
	// CreateTemp is: whoever can write in the store could otherwise plant a
	// link at a guessable name, and an open that follows it would truncate
	// and fill whatever file in the store the link names. O_EXCL refuses any
	// existing name, a link included, without following it.
	var f *os.File
	var tmp string
	for try := 0; ; try++ {
		var nb [12]byte
		if _, err := rand.Read(nb[:]); err != nil {
			return err
		}
		tmp = filepath.Join(filepath.Dir(rel), ".dcn-"+hex.EncodeToString(nb[:])+".tmp")
		var err error
		f, err = r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) || try >= 8 {
			return err
		}
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = r.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = r.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = r.Remove(tmp)
		return err
	}
	if err := r.Rename(tmp, rel); err != nil {
		_ = r.Remove(tmp)
		return err
	}
	return nil
}
