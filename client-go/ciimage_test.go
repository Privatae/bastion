package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The Go toolchain image is pinned by digest in deploy/build.sh, which builds
// releases, and again in each forge's CI, so CI tests with the compiler the
// release is built with. GitHub's workflow checks that the three agree, but
// only GitHub runs that file, and only once a commit is published there. This
// test runs wherever go test runs, so a digest changed in one place and not the
// others fails before the change is merged.
var (
	releaseImageRe = regexp.MustCompile(`(?m)^GO_IMAGE="(golang@sha256:[0-9a-f]{64})"$`)
	giteaImageRe   = regexp.MustCompile(`(?m)^  GO_IMAGE: (\S+)$`)
	githubImageRe  = regexp.MustCompile(`(?m)^      image: (\S+)$`)
)

func TestCIUsesTheReleaseGoImage(t *testing.T) {
	read := func(rel string) string {
		data, err := os.ReadFile(filepath.Join("..", rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	release := releaseImageRe.FindAllStringSubmatch(read("deploy/build.sh"), -1)
	if len(release) != 1 {
		t.Fatalf(`deploy/build.sh: want one GO_IMAGE="golang@sha256:<64 hex>" line, found %d`, len(release))
	}
	want := release[0][1]
	for _, c := range []struct {
		rel string
		re  *regexp.Regexp
		n   int
	}{
		{".gitea/workflows/ci.yml", giteaImageRe, 1},
		{".github/workflows/ci.yml", githubImageRe, 3},
	} {
		got := c.re.FindAllStringSubmatch(read(c.rel), -1)
		if len(got) != c.n {
			t.Errorf("%s: want %d image line(s), found %d", c.rel, c.n, len(got))
		}
		for _, g := range got {
			if g[1] != want {
				t.Errorf("%s names %s; deploy/build.sh builds releases with %s", c.rel, g[1], want)
			}
		}
	}
}
