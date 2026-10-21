//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The decisions are in mcpconfig_winopen.go; this file makes the calls.

// The values mcpconfig_winopen.go spells out must be Windows' own: each line
// fails to compile if one differs.
var (
	_ = [1]struct{}{}[mcpWinFileTypeDisk^windows.FILE_TYPE_DISK]
	_ = [1]struct{}{}[mcpWinAttrDirectory^windows.FILE_ATTRIBUTE_DIRECTORY]
	_ = [1]struct{}{}[mcpWinAttrDevice^windows.FILE_ATTRIBUTE_DEVICE]
	_ = [1]struct{}{}[mcpWinAttrReparse^windows.FILE_ATTRIBUTE_REPARSE_POINT]
)

var mcpAdminOwners = mcpWinAdminOwners

// mcpOpenRegular opens path with CreateFile and keeps it only when the
// handle is a regular file on disk (mcpWinOpenWith). It shares read, write
// and delete with everyone else: the agent client that owns the file must be
// able to save it, including by replacing it, while this reads it.
func mcpOpenRegular(path string) (*os.File, string, error) {
	return mcpWinOpenWith(mcpWinSystemOps, path)
}

var mcpWinSystemOps = mcpWinOps{
	openPath:    mcpWinCreateFile,
	handleInfo:  mcpWinHandleFacts,
	closeHandle: func(h uintptr) { windows.CloseHandle(windows.Handle(h)) },
	asFile:      func(h uintptr, path string) *os.File { return os.NewFile(h, path) },
}

func mcpWinCreateFile(path string) (uintptr, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return uintptr(h), nil
}

// mcpWinHandleFacts reads the type, the attributes and the owner from the
// handle. GENERIC_READ carries READ_CONTROL, which GetSecurityInfo needs for
// the owner; an owner that cannot be read is left "" and the file is then
// read only where no owner check applies.
func mcpWinHandleFacts(h uintptr) (mcpWinHandleInfo, error) {
	wh := windows.Handle(h)
	var i mcpWinHandleInfo
	t, err := windows.GetFileType(wh)
	if err != nil {
		return i, err
	}
	i.FileType = t
	if t != windows.FILE_TYPE_DISK {
		return i, nil // refused by mcpWinRegular; nothing more to ask it
	}
	var bi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(wh, &bi); err != nil {
		return i, err
	}
	i.Attributes = bi.FileAttributes
	if sd, err := windows.GetSecurityInfo(wh, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION); err == nil {
		if o, _, err := sd.Owner(); err == nil && o != nil {
			i.Owner = o.String()
		}
	}
	return i, nil
}

// mcpPathOwner is the SID whose profile dir is, from the ProfileList the
// User Profile Service keeps
// (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>,
// value ProfileImagePath). A directory it does not name, or names twice,
// gives mcpOwnerUnknown, so only SYSTEM's and the Administrators group's
// files are read there.
func mcpPathOwner(dir string) string {
	return mcpWinProfileSID(dir, mcpWinProfiles())
}

func mcpWinProfiles() map[string]string {
	out := map[string]string{}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return out
	}
	defer k.Close()
	sids, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return out
	}
	for _, sid := range sids {
		sk, err := registry.OpenKey(k, sid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		p, typ, err := sk.GetStringValue("ProfileImagePath")
		sk.Close()
		if err != nil {
			continue
		}
		if typ == registry.EXPAND_SZ {
			if x, err := registry.ExpandString(p); err == nil {
				p = x
			}
		}
		out[sid] = p
	}
	return out
}
