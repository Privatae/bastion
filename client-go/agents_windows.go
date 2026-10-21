//go:build windows

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows enumeration for the observe plane.
//
// This is the gap that mattered most: the bastion already SHIPS a Windows
// binary and enforces its grants there, but both enumerators were /proc and
// `ss`, so a Windows box observed nothing at all while reporting healthy. On
// the fleets where "we have machines we have no visibility of" is the actual
// problem, those machines are overwhelmingly Windows.
//
// Nothing here is a new dependency: golang.org/x/sys was already in the module
// graph, and every struct layout below is taken from ITS definitions via
// unsafe.Offsetof rather than hardcoded — so a layout change upstream moves
// our offsets with it instead of silently corrupting a read.
//
// Two enumerators:
//
//	processes    CreateToolhelp32Snapshot, then the PEB for the command line.
//	             Toolhelp gives the image name only, and on Windows the agent
//	             worth catching (claude-code, an npm package) runs as node.exe —
//	             so without the command line the common case is invisible.
//	connections  GetExtendedTcpTable (iphlpapi), IPv4 and IPv6. Deliberately
//	             NOT `netstat -ano`: netstat's STATE column is localized, so
//	             parsing it would silently find nothing on a non-English
//	             Windows. The API returns a numeric state instead.
//
// Every per-process read is best-effort. Reading another process's memory
// needs rights the bastion may not hold (a process of another user, or an
// elevated one, when the bastion is not itself elevated). A refusal yields an
// empty command line or delegation tag, which is the SAME conservative outcome
// as Linux when /proc/PID/environ is unreadable: the agent is still observed,
// and an unreadable tag reads as unrequested, which surfaces it rather than
// hiding it.

const (
	agentScanSupported = true
	agentScanKind      = "toolhelp+iphlpapi"
)

// Offsets are derived from the x/sys/windows struct definitions, never written
// down as literals: PEB.ProcessParameters, RTL_USER_PROCESS_PARAMETERS's
// CommandLine and Environment, and NTUnicodeString.Buffer.
var (
	_peb  windows.PEB
	_rupp windows.RTL_USER_PROCESS_PARAMETERS
	_ntus windows.NTUnicodeString

	offPEBProcessParameters = unsafe.Offsetof(_peb.ProcessParameters)
	offRUPPCommandLine      = unsafe.Offsetof(_rupp.CommandLine)
	offRUPPEnvironment      = unsafe.Offsetof(_rupp.Environment)
	offNTUSBuffer           = unsafe.Offsetof(_ntus.Buffer)

	ptrSize = int(unsafe.Sizeof(uintptr(0)))
)

// winEnvReadSizes: the environment block has no length we can read portably
// (the size field's offset moved across Windows releases), so we read a bounded
// window and stop at the block's own double-NUL terminator. A read that runs
// off the end of the mapped region fails wholesale, so we step down rather than
// give up — a 4 KiB environment is still worth having.
var winEnvReadSizes = []int{64 * 1024, 16 * 1024, 4 * 1024}

const winCmdlineMax = 32 * 1024

func readRemote(h windows.Handle, addr uintptr, n int) ([]byte, error) {
	if addr == 0 || n <= 0 {
		return nil, errors.New("remote read: bad address or size")
	}
	buf := make([]byte, n)
	var got uintptr
	if err := windows.ReadProcessMemory(h, addr, &buf[0], uintptr(n), &got); err != nil {
		return nil, err
	}
	if int(got) < n {
		return buf[:got], nil
	}
	return buf, nil
}

func readRemotePtr(h windows.Handle, addr uintptr) (uintptr, error) {
	b, err := readRemote(h, addr, ptrSize)
	if err != nil || len(b) < ptrSize {
		if err == nil {
			err = errors.New("remote read: short pointer")
		}
		return 0, err
	}
	if ptrSize == 8 {
		return uintptr(binary.LittleEndian.Uint64(b)), nil
	}
	return uintptr(binary.LittleEndian.Uint32(b)), nil
}

// winOpenForRead opens a process for the two rights the reads below need.
// PROCESS_QUERY_LIMITED_INFORMATION (not the full QUERY_INFORMATION) is the
// least privilege that still answers NtQueryInformationProcess.
func winOpenForRead(pid int) (windows.Handle, error) {
	return windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ,
		false, uint32(pid))
}

// winImagePath is the KERNEL's record of which file a process runs, from an
// already-open handle: QueryFullProcessImageName, which reads the image path
// the loader recorded rather than anything in the process's own memory.
//
// NOT Toolhelp32's PROCESSENTRY32.ExeFile — the `exe` local in scanProcesses
// below, and origin_windows.go:50. That field is a BASENAME with no directory
// at all, so "claude.exe" under C:\Users\user\AppData\... and "claude.exe"
// dropped in %TEMP% are one string. A basename cannot be an identity.
//
// Flags 0, never PROCESS_NAME_NATIVE: the Win32 form (C:\...) is what a person
// reading the page recognises and what another tool on the box would print.
// The native form names the same file through a device path
// (\Device\HarddiskVolume3\...) whose volume numbering is not stable across
// boots.
//
// Two buffer sizes, the shape winEnvReadSizes above already uses. MAX_PATH is
// not the limit on a machine with long paths enabled, so one try is not enough;
// past 4096 there is no point trying, because sanitizeExePath refuses a path
// that long anyway (agents_parse.go) and the extra pass would only produce a
// value this function throws away. A refusal — a process of another user, or an
// elevated one when the bastion is not — yields "".
func winImagePath(h windows.Handle) string {
	for _, n := range []uint32{windows.MAX_PATH, 4096} {
		buf := make([]uint16, n)
		size := n
		err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size)
		if err == nil {
			return sanitizeExePath(windows.UTF16ToString(buf[:size]))
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return "" // a refusal, not a small buffer: a bigger one changes nothing
		}
	}
	return ""
}

// winProcessParams walks PBI -> PEB -> ProcessParameters and returns the
// remote address of the parameter block.
func winProcessParams(h windows.Handle) (uintptr, error) {
	var pbi windows.PROCESS_BASIC_INFORMATION
	if err := windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation,
		unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), nil); err != nil {
		return 0, err
	}
	peb := uintptr(unsafe.Pointer(pbi.PebBaseAddress))
	if peb == 0 {
		return 0, errors.New("process params: no PEB")
	}
	return readRemotePtr(h, peb+offPEBProcessParameters)
}

// winCmdline reads a process's full command line out of its PEB.
func winCmdline(h windows.Handle) string {
	params, err := winProcessParams(h)
	if err != nil || params == 0 {
		return ""
	}
	us, err := readRemote(h, params+offRUPPCommandLine, int(unsafe.Sizeof(_ntus)))
	if err != nil || len(us) < int(offNTUSBuffer)+ptrSize {
		return ""
	}
	length := int(binary.LittleEndian.Uint16(us[0:2])) // bytes, not code units
	if length <= 0 {
		return ""
	}
	if length > winCmdlineMax {
		length = winCmdlineMax
	}
	bufAddr, err := readRemotePtr(h, params+offRUPPCommandLine+offNTUSBuffer)
	if err != nil || bufAddr == 0 {
		return ""
	}
	raw, err := readRemote(h, bufAddr, length)
	if err != nil || len(raw) < 2 {
		return ""
	}
	u16 := make([]uint16, len(raw)/2)
	for i := range u16 {
		u16[i] = uint16(raw[i*2]) | uint16(raw[i*2+1])<<8
	}
	return windows.UTF16ToString(u16)
}

// winEnvValue reads one variable out of a process's environment block.
func winEnvValue(h windows.Handle, key string) string {
	params, err := winProcessParams(h)
	if err != nil || params == 0 {
		return ""
	}
	envAddr, err := readRemotePtr(h, params+offRUPPEnvironment)
	if err != nil || envAddr == 0 {
		return ""
	}
	for _, n := range winEnvReadSizes {
		raw, err := readRemote(h, envAddr, n)
		if err != nil || len(raw) == 0 {
			continue
		}
		if v := parseWinEnvBlock(raw, key); v != "" {
			return v
		}
		// A successful read that simply lacks the key is an answer, not a
		// reason to retry smaller.
		return ""
	}
	return ""
}

// winParents caches the pid -> parent map from the last Toolhelp walk, so the
// shared classifier's per-pid parent lookups cost nothing extra.
var winParents = struct {
	sync.Mutex
	m map[int]int
}{m: map[int]int{}}

func procParent(pid int) int {
	winParents.Lock()
	defer winParents.Unlock()
	return winParents.m[pid]
}

// winCreationTime is when a process started, in 100ns FILETIME units.
func winCreationTime(pid int) (int64, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0, false
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return 0, false
	}
	return created.Nanoseconds(), true
}

// processParents walks a fresh snapshot for the CONTAIN path, and keeps only
// parent links that can be true.
//
// Toolhelp's ParentProcessID is the pid of the process that CREATED this one,
// recorded once and never updated. When that creator exits, Windows recycles
// its pid; a later process (say, the agent being contained) can receive it,
// and every orphan the old creator left behind then reads as the agent's
// child. On a kill path that is an unrelated process terminated. A real
// parent is always older than its child, so a link is kept only when both
// creation times are readable and the child started after the parent; an
// unreadable process contributes no link at all (fail closed: no kill). Linux
// and macOS reparent orphans to a live process and need none of this.
func processParents() map[int]int {
	out := map[int]int{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	raw := map[int]int{}
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if pid, pp := int(e.ProcessID), int(e.ParentProcessID); pid > 0 && pp > 0 {
			raw[pid] = pp
		}
	}
	created := map[int]int64{}
	timeOf := func(pid int) (int64, bool) {
		if t, ok := created[pid]; ok {
			return t, t > 0
		}
		t, ok := winCreationTime(pid)
		if !ok {
			created[pid] = 0
			return 0, false
		}
		created[pid] = t
		return t, true
	}
	for pid, pp := range raw {
		ct, okc := timeOf(pid)
		pt, okp := timeOf(pp)
		if okc && okp && ct >= pt {
			out[pid] = pp
		}
	}
	winParents.Lock()
	winParents.m = raw // classification (not killing) may use the raw links
	winParents.Unlock()
	return out
}

// scanProcesses: an error is a snapshot that did not happen (Toolhelp can
// fail transiently), never an empty box; the heartbeat withholds `agents`.
func scanProcesses() (map[int]agentObs, error) {
	out := map[int]agentObs{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("process snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	self := os.Getpid()
	parents := map[int]int{}
	defer func() {
		winParents.Lock()
		winParents.m = parents
		winParents.Unlock()
	}()
	// The loop ends on ERROR_NO_MORE_FILES; any other error — Process32First
	// refusing a snapshot it just handed out — is a walk that did not happen.
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		pid := int(e.ProcessID)
		if pp := int(e.ParentProcessID); pid > 0 && pp > 0 {
			parents[pid] = pp
		}
		if pid <= 0 || pid == self {
			continue
		}
		exe := windows.UTF16ToString(e.ExeFile[:])
		base := binBase(exe)
		_, direct := agentBinaries[base]
		_, autoDirect := automationBinaries[base]
		if !direct && !autoDirect && !interpreters[base] {
			continue // not a candidate: never pay for a memory read
		}
		// argv[0] comes from Toolhelp (always right); the raw command line is
		// appended as one element purely so the substring rules can see it.
		// No tokenizing: Windows command lines are a single quoted string, and
		// splitting one on spaces mangles "C:\Program Files\..." into a
		// basename that matches nothing.
		// ONE handle for all three reads. Opening the process per field cost
		// three OpenProcess/CloseHandle round trips for every candidate on
		// every beat, and could even disagree with itself if the pid was
		// recycled between them.
		argv := []string{exe}
		cmdline, user, token, image := "", "", "", ""
		if h, herr := winOpenForRead(pid); herr == nil {
			cmdline = winCmdline(h)
			user = winTokenUser(h)
			token = winAgentToken(h)
			image = winImagePath(h)
			windows.CloseHandle(h)
		} else if h, herr := windows.OpenProcess(
			windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)); herr == nil {
			// The image path needs strictly LESS than the reads above:
			// QueryFullProcessImageName takes QUERY_LIMITED_INFORMATION alone,
			// while the PEB walk also needs VM_READ. So a process whose memory
			// this bastion may not read can still say which FILE it is running —
			// and that is the difference between an observation the user can
			// mark as theirs and one they cannot (sanction.go refuses to mark an
			// observation with no path). Without this branch, every process that
			// refused the combined open would be permanently unsanctionable.
			image = winImagePath(h)
			windows.CloseHandle(h)
		}
		if cmdline != "" {
			argv = append(argv, cmdline)
		}
		sig, auto, ok := matchSignature(argv)
		if !ok {
			continue
		}
		shown := cmdline
		if shown == "" {
			shown = exe
		}
		out[pid] = agentObs{PID: pid, User: user, Signature: sig,
			Cmdline: truncate(shown, 200), Exe: image,
			DelegationToken: token, raw: shown, automation: auto}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, fmt.Errorf("process walk: %w", err)
	}
	return out, nil
}

// ── connections: GetExtendedTcpTable ────────────────────────────────────────

var (
	modIphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	winAFInet  = 2  // AF_INET
	winAFInet6 = 23 // AF_INET6
	// TCP_TABLE_OWNER_PID_CONNECTIONS — connected sockets with their owning pid.
	winTCPTableOwnerPIDConnections = 4
	winErrInsufficientBuffer       = 122
)

// extendedTCPTable fetches the owner-pid TCP table for one address family.
// Two-pass sizing, with a couple of retries because the table can grow between
// the sizing call and the read.
func extendedTCPTable(af uint32) ([]byte, error) {
	var size uint32
	r, _, _ := procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0,
		uintptr(af), winTCPTableOwnerPIDConnections, 0)
	if r != 0 && r != winErrInsufficientBuffer {
		return nil, syscall.Errno(r)
	}
	for attempt := 0; attempt < 3; attempt++ {
		if size == 0 {
			return nil, nil
		}
		buf := make([]byte, size)
		r, _, _ = procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)), 0, uintptr(af), winTCPTableOwnerPIDConnections, 0)
		if r == 0 {
			return buf, nil
		}
		if r != winErrInsufficientBuffer {
			return nil, syscall.Errno(r)
		}
		// size now holds the larger requirement; loop and try again.
	}
	return nil, errors.New("GetExtendedTcpTable: table kept growing")
}

func scanConnections() []connObs {
	self := os.Getpid()
	conns := []connObs{}
	for _, fam := range []struct {
		af uint32
		v6 bool
	}{{winAFInet, false}, {winAFInet6, true}} {
		buf, err := extendedTCPTable(fam.af)
		if err != nil || len(buf) == 0 {
			continue // one family failing must not lose the other
		}
		conns = append(conns, parseTCPTable(buf, fam.v6, self)...)
	}
	return conns
}

// ── per-process detail ──────────────────────────────────────────────────────

// winTokenUser resolves the owner of an ALREADY-OPEN process handle, so a
// caller holding one handle can read every field from it.
func winTokenUser(h windows.Handle) string {
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return ""
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil || tu.User.Sid == nil {
		return ""
	}
	account, domain, _, err := tu.User.Sid.LookupAccount("")
	if err != nil {
		return tu.User.Sid.String()
	}
	if domain != "" {
		return domain + `\` + account
	}
	return account
}

func procUser(pid int) string {
	h, err := winOpenForRead(pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	return winTokenUser(h)
}

func procCmdline(pid int) string {
	h, err := winOpenForRead(pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	return truncate(strings.TrimSpace(winCmdline(h)), 200)
}

// procExe is the KERNEL's executable path for one pid. It opens with
// QUERY_LIMITED_INFORMATION alone — the least right that answers
// QueryFullProcessImageName, and less than winOpenForRead asks for — so a
// process whose memory is closed to this bastion still reports which file it
// runs. "" when even that handle is refused.
func procExe(pid int) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	return winImagePath(h)
}

// winAgentToken reads the delegation tag out of an already-open process
// handle, under either accepted name. One handle, both names: the environment
// block is read per call, and re-opening the process for the second name could
// land on a recycled pid.
func winAgentToken(h windows.Handle) string {
	for _, name := range agentTokenEnvNames {
		if tok := winEnvValue(h, name); tok != "" {
			return tok
		}
	}
	return ""
}

// procEnvToken reads the host-issued delegation tag (PRIVATAE_AGENT_TOKEN, or
// its older name; see agentTokenEnvNames) from the agent's environment block.
func procEnvToken(pid int) string {
	h, err := winOpenForRead(pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	return winAgentToken(h)
}
