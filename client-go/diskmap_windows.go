package main

// The two platform questions the disk map asks, answered for Windows.

import (
	"fmt"
	"io/fs"

	"golang.org/x/sys/windows"
)

// dmDeviceOf on Windows says "no device information", and that is the correct
// answer rather than a stub.
//
// FileInfo.Sys() here is a *syscall.Win32FileAttributeData, which carries
// attributes and timestamps and NO volume identity — the field a caller would
// want (dwVolumeSerialNumber) only comes from GetFileInformationByHandle,
// which needs an OPEN HANDLE on the file. Opening every directory to ask what
// volume it is on is exactly the syscall this unit is not allowed to make, and
// paying it 87,000 times would also be the slowest thing in the walk.
//
// Nothing is lost by saying no, because on Windows the drive letter IS the
// boundary: a walk rooted at C:\ cannot reach D: except through a junction or
// a symlink, and filepath.WalkDir does not follow either (fs.DirEntry is
// lstat-shaped, so a reparse point has IsDir() == false and is never
// descended). The mount-crossing defence unix gets from st_dev, Windows gets
// from not following links — which it has for free and unconditionally.
//
// UNVERIFIED: nothing here has been run on Windows. Cross-compiled and vetted
// for all three Windows targets, code-reviewed on Linux.
func dmDeviceOf(path string) (uint64, bool) { return 0, false }

func dmDeviceOfInfo(fi fs.FileInfo) (uint64, bool) { return 0, false }

// dmVolumeRoots is the machine's FIXED drives, and only the fixed ones.
//
// GetLogicalDrives returns a bitmask of present letters — bit 0 is A:, bit 25
// is Z: — and GetDriveType says what each one is. Both are in
// golang.org/x/sys/windows, which this binary already depends on (go.mod), so
// this costs no new module and no cgo: the whole point of deploy/publish.sh is
// six targets out of one CGO_ENABLED=0 container.
//
// WHY ONLY DRIVE_FIXED, with the others named on the page rather than silently
// dropped:
//
//   - DRIVE_REMOTE is a network share. Walking it sends every directory read
//     over the wire, and on a VPN that is down each one waits for a timeout;
//     a "map my disk" click would appear to hang for minutes and the bytes it
//     eventually counted would not be on this machine at all.
//   - DRIVE_CDROM and DRIVE_REMOVABLE spin up hardware to answer, and an empty
//     drive answers with an error dialog on some configurations.
//   - DRIVE_RAMDISK is memory, not disk, and would be counted as space that
//     could be freed when there is nothing there to free.
//
// WinDirStat opens with "select the drives to scan" for precisely this reason.
// This picks the same default it does and SAYS what it left out, because a map
// that quietly omits a drive is worse than one that names it.
func dmVolumeRoots() (roots []string, notes []string) {
	mask, err := windows.GetLogicalDrives()
	if err != nil || mask == 0 {
		// No answer from the OS is not "no drives". Fall back to the system
		// drive, which is the one that always exists, and say the enumeration
		// failed so a missing D: reads as a known gap rather than as fact.
		notes = append(notes, "this machine's drive list could not be read from Windows, so the map covers C: only")
		return []string{`C:\`}, notes
	}
	var skipped []string
	for bit := uint(0); bit < 26; bit++ {
		if mask&(1<<bit) == 0 {
			continue
		}
		root := fmt.Sprintf("%c:\\", 'A'+rune(bit))
		p, perr := windows.UTF16PtrFromString(root)
		if perr != nil {
			continue
		}
		switch windows.GetDriveType(p) {
		case windows.DRIVE_FIXED:
			roots = append(roots, root)
		case windows.DRIVE_REMOTE:
			skipped = append(skipped, root+" (a network drive — its files are not on this machine)")
		case windows.DRIVE_CDROM:
			skipped = append(skipped, root+" (a disc drive)")
		case windows.DRIVE_REMOVABLE:
			skipped = append(skipped, root+" (a removable drive)")
		case windows.DRIVE_RAMDISK:
			skipped = append(skipped, root+" (a RAM disk — it holds no disk space)")
		}
	}
	if len(roots) == 0 {
		notes = append(notes, "Windows reported no fixed drive on this machine, so the map covers C: only")
		roots = []string{`C:\`}
	}
	for _, s := range skipped {
		notes = append(notes, "not mapped: "+s)
	}
	return roots, notes
}
