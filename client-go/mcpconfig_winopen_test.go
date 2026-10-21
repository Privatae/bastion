package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The Windows open's decisions, with fake handles: Windows itself never runs
// here, and nothing in CI runs on Windows, so this is what checks the rules.
// The SIDs are invented.

const (
	testWinSIDOwner = "S-1-5-21-1000000001-1000000002-1000000003-1201"
	testWinSIDOther = "S-1-5-21-1000000001-1000000002-1000000003-1202"
)

type fakeWinHandles struct {
	info      mcpWinHandleInfo
	infoErr   error
	openErr   error
	openCount int
	closed    []uintptr
	files     []uintptr
	backing   string // a real file the "handle" reads from
}

func (f *fakeWinHandles) ops(t *testing.T) mcpWinOps {
	return mcpWinOps{
		openPath: func(string) (uintptr, error) {
			if f.openErr != nil {
				return 0, f.openErr
			}
			f.openCount++
			return uintptr(100 + f.openCount), nil
		},
		handleInfo:  func(uintptr) (mcpWinHandleInfo, error) { return f.info, f.infoErr },
		closeHandle: func(h uintptr) { f.closed = append(f.closed, h) },
		asFile: func(h uintptr, path string) *os.File {
			f.files = append(f.files, h)
			r, err := os.Open(f.backing)
			if err != nil {
				t.Fatal(err)
			}
			return r
		},
	}
}

func TestMCPWinOpenRefusesWhatIsNotARegularFileOnDisk(t *testing.T) {
	backing := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(backing, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	refused := map[string]mcpWinHandleInfo{
		"symbolic link or junction (reparse point)": {FileType: mcpWinFileTypeDisk, Attributes: mcpWinAttrReparse | 0x20, Owner: testWinSIDOwner},
		"directory":        {FileType: mcpWinFileTypeDisk, Attributes: mcpWinAttrDirectory, Owner: testWinSIDOwner},
		"device attribute": {FileType: mcpWinFileTypeDisk, Attributes: mcpWinAttrDevice, Owner: testWinSIDOwner},
		"character device": {FileType: 0x0002, Owner: testWinSIDOwner},
		"pipe":             {FileType: 0x0003, Owner: testWinSIDOwner},
		"unknown type":     {FileType: 0x0000, Owner: testWinSIDOwner},
	}
	for name, info := range refused {
		fk := &fakeWinHandles{info: info, backing: backing}
		f, _, err := mcpWinOpenWith(fk.ops(t), `C:\Users\demo\.cursor\mcp.json`)
		if f != nil || !errors.Is(err, errMCPNotRegular) {
			t.Errorf("%s: opened (err %v)", name, err)
		}
		if len(fk.closed) != 1 || len(fk.files) != 0 {
			t.Errorf("%s: handle not closed, or made into a file: closed %v files %v", name, fk.closed, fk.files)
		}
	}

	fk := &fakeWinHandles{infoErr: errors.New("query failed"), backing: backing}
	if f, _, err := mcpWinOpenWith(fk.ops(t), `C:\x`); f != nil || err == nil || len(fk.closed) != 1 {
		t.Errorf("a handle that cannot be queried must be closed and refused: %v %v", err, fk.closed)
	}

	fk = &fakeWinHandles{openErr: &os.PathError{Op: "open", Path: `C:\x`, Err: os.ErrNotExist}, backing: backing}
	if _, _, err := mcpWinOpenWith(fk.ops(t), `C:\x`); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing file must stay a missing file (not counted unreadable): %v", err)
	}

	// A plain file (FILE_ATTRIBUTE_ARCHIVE) is opened, and its owner comes back.
	fk = &fakeWinHandles{info: mcpWinHandleInfo{FileType: mcpWinFileTypeDisk, Attributes: 0x20, Owner: testWinSIDOwner}, backing: backing}
	f, owner, err := mcpWinOpenWith(fk.ops(t), `C:\x`)
	if err != nil || f == nil || owner != testWinSIDOwner || len(fk.closed) != 0 {
		t.Fatalf("a regular file was refused: %v %q %v", err, owner, fk.closed)
	}
	f.Close()

	// An owner that could not be read is never an owner that matches.
	fk = &fakeWinHandles{info: mcpWinHandleInfo{FileType: mcpWinFileTypeDisk, Attributes: 0x80}, backing: backing}
	f, owner, err = mcpWinOpenWith(fk.ops(t), `C:\x`)
	if err != nil || owner != mcpOwnerUnknown {
		t.Fatalf("unread owner: %v %q", err, owner)
	}
	f.Close()
	if mcpOwnerAllowed(owner, mcpOwnerUnknown, mcpWinAdminOwners) {
		t.Fatal("an unread owner matched an unknown profile owner")
	}
}

func TestMCPWinOwnerRules(t *testing.T) {
	for _, c := range []struct {
		file, want string
		ok         bool
	}{
		{testWinSIDOwner, testWinSIDOwner, true},
		{"S-1-5-18", testWinSIDOwner, true},     // SYSTEM
		{"S-1-5-32-544", testWinSIDOwner, true}, // Administrators
		{testWinSIDOther, testWinSIDOwner, false},
		{"S-1-1-0", testWinSIDOwner, false}, // Everyone
		{"", testWinSIDOwner, false},
		{mcpOwnerUnknown, testWinSIDOwner, false},
		{testWinSIDOther, mcpOwnerUnknown, false},
		{"S-1-5-18", mcpOwnerUnknown, true},
		{testWinSIDOther, mcpNoOwnerCheck, true},
	} {
		if got := mcpOwnerAllowed(c.file, c.want, mcpWinAdminOwners); got != c.ok {
			t.Errorf("file owner %q read for %q: allowed %v, want %v", c.file, c.want, got, c.ok)
		}
	}
}

func TestMCPWinProfileSID(t *testing.T) {
	profiles := map[string]string{
		"S-1-5-18":                           `C:\Windows\system32\config\systemprofile`,
		testWinSIDOwner:                      `C:\Users\demo`,
		testWinSIDOwner + ".bak":             `C:\Users\demo`,
		testWinSIDOther:                      `C:\Users\other`,
		"S-1-5-21-1000000001-1000000002-9-1": `C:\Users\twice`,
		"S-1-5-21-1000000001-1000000002-9-2": `C:\Users\twice`,
	}
	for dir, want := range map[string]string{
		`C:\Users\demo`:   testWinSIDOwner,
		`c:\users\DEMO\`:  testWinSIDOwner,
		`C:/Users/demo`:   testWinSIDOwner,
		`C:\Users\other`:  testWinSIDOther,
		`C:\Users\twice`:  mcpOwnerUnknown,
		`C:\Users\nobody`: mcpOwnerUnknown,
	} {
		if got := mcpWinProfileSID(dir, profiles); got != want {
			t.Errorf("%s: %q, want %q", dir, got, want)
		}
	}
}

// End to end through mcpReadFileAs with the Windows open's rules: a file in a
// profile that another account owns is not read and is counted, one SYSTEM
// owns is read.
func TestMCPReadFileAsWindowsOwnerRules(t *testing.T) {
	backing := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(backing, []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	oldOpen, oldAdmins := mcpOpenRegularFn, mcpAdminOwners
	t.Cleanup(func() { mcpOpenRegularFn, mcpAdminOwners = oldOpen, oldAdmins })
	mcpAdminOwners = mcpWinAdminOwners
	for _, c := range []struct {
		owner   string
		read    bool
		foreign int
	}{
		{testWinSIDOwner, true, 0},
		{"S-1-5-18", true, 0},
		{testWinSIDOther, false, 1},
		{"", false, 1},
	} {
		fk := &fakeWinHandles{info: mcpWinHandleInfo{FileType: mcpWinFileTypeDisk, Attributes: 0x20, Owner: c.owner}, backing: backing}
		mcpOpenRegularFn = func(p string) (*os.File, string, error) { return mcpWinOpenWith(fk.ops(t), p) }
		var scan mcpConfigScan
		_, ok := mcpReadFileAs(`C:\Users\demo\.cursor\mcp.json`, testWinSIDOwner, &scan)
		if ok != c.read || scan.ForeignOwner != c.foreign {
			t.Errorf("owner %q: read %v foreign %d, want %v %d", c.owner, ok, scan.ForeignOwner, c.read, c.foreign)
		}
	}
}
