package main

import (
	"os"
	"sort"
	"strings"
)

// THE WINDOWS OPEN, DECIDED WHERE A LINUX TEST CAN SEE IT.
//
// mcpconfig_open_windows.go opens a config path with CreateFile and asks the
// HANDLE what it holds; every decision about the answer is here, with no
// build tag, so the Linux test run checks the Windows rules with fake handles
// (mcpconfig_winopen_test.go). Nothing here calls Windows.
//
// The open does not follow a reparse point at the last component
// (FILE_FLAG_OPEN_REPARSE_POINT): a symbolic link, junction or other
// reparse point at a config path is opened as itself, seen as a reparse
// point, and refused. What is checked is the handle that will be read, so
// there is no gap between a look and an open for a swap to fall into. A
// directory, a device, a pipe or anything else that is not a file on disk is
// refused the same way. A reparse point in a directory ABOVE the file is
// followed, as for any program opening the path; the file it leads to must
// then be owned by the account whose profile it is read for, or by SYSTEM or
// the Administrators group (mcpOwnerAllowed), so a link into another
// account's profile reads nothing of it.

// The Windows values the decision reads, from the SDK headers (winbase.h,
// winnt.h) as golang.org/x/sys/windows carries them: FILE_TYPE_DISK,
// FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_REPARSE_POINT.
const (
	mcpWinFileTypeDisk  = 0x0001
	mcpWinAttrDirectory = 0x0010
	mcpWinAttrDevice    = 0x0040
	mcpWinAttrReparse   = 0x0400
)

// mcpWinAdminOwners: the owners a file in any account's profile may have
// besides that account. SYSTEM (S-1-5-18), and the Administrators group
// (S-1-5-32-544), which is the default owner of what an elevated
// administrator creates.
var mcpWinAdminOwners = map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}

// mcpWinHandleInfo is what the open read from the handle it holds.
type mcpWinHandleInfo struct {
	FileType   uint32 // GetFileType
	Attributes uint32 // GetFileInformationByHandle's FileAttributes
	Owner      string // the owner SID from GetSecurityInfo; "" when unread
}

// mcpWinRegular: the handle is a file on disk that is not a directory, a
// device or a reparse point.
func mcpWinRegular(i mcpWinHandleInfo) bool {
	return i.FileType == mcpWinFileTypeDisk &&
		i.Attributes&(mcpWinAttrDirectory|mcpWinAttrDevice|mcpWinAttrReparse) == 0
}

// mcpWinOps are the Windows calls the open makes, as values so a test can
// stand fakes in for them. The field names are not method names anywhere in
// the package: the claims test resolves a call through a value by name.
type mcpWinOps struct {
	openPath    func(path string) (uintptr, error)
	handleInfo  func(h uintptr) (mcpWinHandleInfo, error)
	closeHandle func(h uintptr)
	asFile      func(h uintptr, path string) *os.File
}

// mcpWinOpenWith opens path, checks the handle, and hands back the file and
// its owner SID. A handle that is refused is closed before return and never
// becomes a file.
func mcpWinOpenWith(ops mcpWinOps, path string) (*os.File, string, error) {
	h, err := ops.openPath(path)
	if err != nil {
		return nil, "", err
	}
	info, err := ops.handleInfo(h)
	if err != nil {
		ops.closeHandle(h)
		return nil, "", &os.PathError{Op: "query", Path: path, Err: err}
	}
	if !mcpWinRegular(info) {
		ops.closeHandle(h)
		return nil, "", errMCPNotRegular
	}
	owner := info.Owner
	if owner == "" {
		owner = mcpOwnerUnknown
	}
	return ops.asFile(h, path), owner, nil
}

// mcpWinProfileSID is the SID whose profile directory is dir, from the
// ProfileList (SID to ProfileImagePath, already expanded). mcpOwnerUnknown
// when no SID or more than one names it; only an administrator's or
// SYSTEM's files are then read there.
func mcpWinProfileSID(dir string, profiles map[string]string) string {
	norm := func(p string) string {
		return strings.ToLower(strings.TrimRight(strings.ReplaceAll(p, "/", `\`), `\`))
	}
	want := norm(dir)
	var hits []string
	for sid, p := range profiles {
		if strings.HasPrefix(sid, "S-1-") && !strings.Contains(sid, ".") && norm(p) == want {
			hits = append(hits, sid)
		}
	}
	sort.Strings(hits)
	if len(hits) != 1 {
		return mcpOwnerUnknown
	}
	return hits[0]
}
