package main

// deltacache.go — the executable-digest cache that makes a delta on every
// heartbeat affordable.
//
// MEASURED (a live machine, 230 live processes, as root): a full baseline
// pass costs 2.9–3.0 s, of which the /proc walk is
// 12 ms and the SHA-256 of 204 executables is 2.7 s. So 92% of the cost is
// hashing, and the second and third passes cost the same as the first — it is
// CPU-bound on the hash, not cold page cache, and repeating it will not get
// cheaper by itself.
//
// The delta runs on the heartbeat's cadence (60 s, run.go:596). Re-hashing
// every executable on the box every minute is 5% of a core for ever, on a
// program whose whole promise is to stay out of the user's way. So the digest
// is cached — and the only question a cache like this has to answer is whether
// it can ever hand back a stale digest for a file that has changed, because
// that is precisely the event the delta exists to notice.
//
// THE KEY IS WHAT MAKES IT SAFE, and every part of it is load-bearing:
//
//	dev + inode  the file's IDENTITY. Replacing a binary — the ordinary package
//	             upgrade, and the ordinary swap — writes a NEW inode, so the old
//	             entry can never be consulted for the new file.
//	size         the free change signal.
//	ctime        the inode's own change time. It moves on ANY write to the file
//	             or its metadata — INCLUDING the write that puts the old mtime
//	             back — and no syscall sets it. That is the field that closes
//	             the in-place-overwrite hole the first two leave open.
//
// MTIME IS DELIBERATELY NOT IN IT. utimes(2) sets it to anything the caller
// likes, so it adds no guarantee ctime does not already give; an earlier
// version of this comment said the key was five fields when the code has
// always used four, and a doc that overstates a security property is worse
// than one that says nothing.
//
// The bound on the ctime claim, stated rather than implied: no syscall sets it,
// but root can move the system clock. The key carries nanoseconds, so that
// needs a second-granularity filesystem to be useful — and a root who can do
// it can also stop the daemon, which is a louder thing to notice.
//
// WINDOWS IS ONE FIELD WEAKER and says so. Go's os.FileInfo.Sys() there is a
// syscall.Win32FileAttributeData, which carries creation, access and write
// times and no change time (NTFS keeps one; the Win32 attribute struct does not
// expose it). So a Windows entry is keyed on identity-less size + write time +
// creation time, and deltaCacheWeakTTL below is what covers the difference:
// a weakly-keyed entry is re-hashed on a timer no matter what it claims.
//
// IN MEMORY ONLY, deliberately. A cache on disk would survive restarts and
// would also be a file an attacker could edit to make a swapped binary read as
// already-known — trading the one property this cache has to have for a saving
// measured in seconds, once per process.

import (
	"os"
	"sync"
	"time"
)

// deltaCacheWeakTTL forces a re-hash of an entry whose platform key cannot
// prove the file is unchanged (Windows, and anything whose FileInfo the
// platform helper does not recognise). At the measured 2.7 s for a whole box,
// re-hashing every 15 minutes is 0.3% of one core, and it bounds how long a
// size-and-timestamp-preserving overwrite can read as known.
const deltaCacheWeakTTL = 15 * time.Minute

type digestCacheEntry struct {
	key    string
	strong bool
	at     time.Time
	digest string
	note   string
}

// digestCache is a path -> digest map that re-hashes when the file's key moves.
// The zero value is ready to use.
type digestCache struct {
	mu sync.Mutex
	by map[string]digestCacheEntry
	// hits and misses are for the operator, so "the cache is working" is a
	// number and not a belief. Reported by observe:delta --json.
	//
	// THEY COUNT REPEATS WITHIN A PASS AS WELL AS ACROSS PASSES, and the first
	// pass makes that obvious: 46 distinct executables served 195 processes
	// here, so a COLD pass already reports ~108 hits. Read the miss count for
	// "what did this cost" — it is the one that stops moving once the box is
	// steady.
	hits, misses int
}

// digest answers the same question baselineExeDigest answers, and defers to it
// on a miss rather than re-implementing any of its rules — the size cap, the
// regular-file check and every "could not look" note stay in ONE place, so a
// cached answer and an uncached one can never disagree about anything except
// how long they took.
func (c *digestCache) digest(path string) (digest, note string) {
	fi, err := os.Stat(path)
	if err != nil {
		// No file to key on. Fall through to the uncached path, which turns
		// this into the right sentence about why there is no digest.
		return baselineExeDigest(path)
	}
	key, strong := statIdentity(fi)
	c.mu.Lock()
	e, ok := c.by[path]
	c.mu.Unlock()
	if ok && e.key == key && key != "" &&
		(e.strong || time.Since(e.at) < deltaCacheWeakTTL) {
		c.mu.Lock()
		c.hits++
		c.mu.Unlock()
		return e.digest, e.note
	}
	digest, note = baselineExeDigest(path)
	c.mu.Lock()
	if c.by == nil {
		c.by = map[string]digestCacheEntry{}
	}
	c.misses++
	// A FAILURE IS NEVER CACHED. "could not be read by this account" is a fact
	// about the moment, not about the file: a process whose exe becomes
	// readable — the bastion gaining rights, a mount appearing — must be
	// digested the next time it is asked about, not told for ever that it
	// could not be looked at.
	if digest != "" && key != "" {
		c.by[path] = digestCacheEntry{key: key, strong: strong, at: time.Now(),
			digest: digest, note: note}
	}
	c.mu.Unlock()
	return digest, note
}

// stats reports what the cache did, for the operator's own eyes.
func (c *digestCache) stats() (hits, misses, held int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses, len(c.by)
}

// NO forget(). There was one, described as "used when the baseline is retaken",
// and nothing called it. Retaking the accounting does
// not need it either: a cached digest is keyed on the file's identity and
// change time, so it is either still the right answer or already invalid, and
// dropping the map would only make the next pass pay for a fact it holds.
