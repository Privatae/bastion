//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// errNotPlainFile is openTreeEntry's refusal of a name that is no longer a
// plain file when it is opened.
var errNotPlainFile = errors.New("not a plain file")

// packTree hands the tree under root to sink, walking it by open folder
// (packWorktree says why). Each name is looked at with fstatat and opened
// relative to the folder above it (openTreeEntry, per system), never
// following a link, and it goes in only if the opened file is still the plain
// file or folder that was looked at (same type, device and inode). A pipe or
// device seen as one is never opened, so the walk cannot wait on one; on
// Linux one swapped in between is not opened either, and elsewhere O_NONBLOCK
// and O_NOCTTY cover it. Each left-out entry goes to sink.skip.
func packTree(sink treeSink, root string) error {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: root, Err: err}
	}
	d := os.NewFile(uintptr(fd), root)
	defer d.Close()
	return packFolder(sink, d, fd, "", 0)
}

func packFolder(sink treeSink, d *os.File, dfd int, rel string, depth int) error {
	names, err := readTreeNames(sink, d, rel)
	if err != nil {
		return err
	}
	if err := sink.folder(rel, names); err != nil {
		return err
	}
	for _, name := range names {
		p := name
		if rel != "" {
			p = rel + "/" + name
		}
		var st unix.Stat_t
		if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			sink.skip(p) // gone since the folder was read
			continue
		}
		kind := st.Mode & unix.S_IFMT
		if kind == unix.S_IFDIR && name == ".git" {
			continue
		}
		if (kind != unix.S_IFREG && kind != unix.S_IFDIR) || (kind == unix.S_IFDIR && depth >= maxTreeDepth) {
			sink.skip(p)
			continue
		}
		if packTreeBeforeOpen != nil {
			packTreeBeforeOpen(p)
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY
		if kind == unix.S_IFDIR {
			flags |= unix.O_DIRECTORY
		}
		cfd, err := openTreeEntry(dfd, name, flags)
		if err != nil {
			sink.skip(p) // a link or special file now, or gone
			continue
		}
		err = packOpened(sink, cfd, name, st, p, depth)
		if err != nil {
			return err
		}
	}
	return nil
}

// packOpened hands sink the entry opened as fd, and for a folder what is in it,
// if it is still the entry fstatat saw; it closes fd.
func packOpened(sink treeSink, fd int, name string, seen unix.Stat_t, p string, depth int) error {
	var got unix.Stat_t
	if err := unix.Fstat(fd, &got); err != nil {
		unix.Close(fd)
		return fmt.Errorf("stat %q: %w", p, err)
	}
	kind := got.Mode & unix.S_IFMT
	if kind != seen.Mode&unix.S_IFMT || got.Dev != seen.Dev || got.Ino != seen.Ino {
		unix.Close(fd)
		sink.skip(p) // swapped between the look and the open
		return nil
	}
	// A plain file or folder now: back to blocking reads, so os.File reads it
	// as it reads any file it opened itself.
	if err := unix.SetNonblock(fd, false); err != nil {
		unix.Close(fd)
		return fmt.Errorf("open %q: %w", p, err)
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %q: %w", p, err)
	}
	if err := sink.put(f, fi, p); err != nil {
		return err
	}
	if kind == unix.S_IFDIR {
		return packFolder(sink, f, fd, p, depth+1)
	}
	return nil
}
