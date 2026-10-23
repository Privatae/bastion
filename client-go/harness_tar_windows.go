//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// packTree hands the tree under root to sink (packWorktree says why it is
// walked this way). Every name is opened through an os.Root at the tree, so
// no link, junction or name swapped in while it is packed can open a file
// outside the tree; an entry goes in only if the opened file is the plain
// file or folder that was looked at. Each left-out entry goes to sink.skip.
func packTree(sink treeSink, root string) error {
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer r.Close()
	return packRootFolder(sink, r, "", 0)
}

func packRootFolder(sink treeSink, r *os.Root, rel string, depth int) error {
	open := rel
	if open == "" {
		open = "."
	}
	d, err := r.Open(open)
	if err != nil {
		return fmt.Errorf("open folder %q: %w", rel, err)
	}
	names, err := readTreeNames(sink, d, filepath.ToSlash(rel))
	d.Close()
	if err != nil {
		return err
	}
	if err := sink.folder(filepath.ToSlash(rel), names); err != nil {
		return err
	}
	for _, name := range names {
		p := filepath.Join(rel, name)
		tp := filepath.ToSlash(p)
		seen, err := r.Lstat(p)
		if err != nil {
			sink.skip(tp)
			continue
		}
		if seen.IsDir() && name == ".git" {
			continue
		}
		if (!seen.Mode().IsRegular() && !seen.IsDir()) || (seen.IsDir() && depth >= maxTreeDepth) {
			sink.skip(tp)
			continue
		}
		if packTreeBeforeOpen != nil {
			packTreeBeforeOpen(tp)
		}
		f, err := r.Open(p)
		if err != nil {
			sink.skip(tp)
			continue
		}
		fi, err := f.Stat()
		if err != nil || fi.Mode().Type() != seen.Mode().Type() {
			f.Close()
			sink.skip(tp)
			continue
		}
		err = sink.put(f, fi, tp)
		f.Close()
		if err != nil {
			return err
		}
		if fi.IsDir() {
			if err := packRootFolder(sink, r, p, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
