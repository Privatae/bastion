package main

import (
	"strings"

	"rsc.io/qr"
)

// qrTerminal renders text as a QR block a phone camera can actually read from a
// terminal window.
//
// Two things make this work that are easy to get wrong:
//
//  1. ORIENTATION. Most scanners want dark modules on a light field. A terminal
//     with a dark theme printing solid blocks produces an INVERTED code, which a
//     lot of authenticator apps silently refuse — you get a code on screen that
//     simply never scans, which is worse than no code because it looks fine. So
//     the colours are set explicitly (white background, black foreground) rather
//     than inherited from the theme.
//
//  2. THE QUIET ZONE. The spec wants 4 clear modules of margin. Without it,
//     scanners cannot find the symbol against surrounding terminal text. It is
//     the single most common reason a hand-rolled terminal QR does not scan.
//
// Half-block glyphs pack two module rows into one character cell, which keeps a
// version-2/3 symbol inside a standard 80x24 window. Rendered at one cell per
// module it would be twice as tall and usually scroll, which is its own failure.
func qrTerminal(text string) (string, error) {
	// M = ~15% recovery. L would make the symbol smaller, but a terminal QR is
	// photographed off a glossy screen at an angle, and the extra redundancy is
	// what absorbs the glare — this is the level `qrencode` defaults to.
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	const quiet = 4
	n := c.Size

	// Anything outside the symbol is light — that IS the quiet zone.
	dark := func(x, y int) bool {
		if x < 0 || y < 0 || x >= n || y >= n {
			return false
		}
		return c.Black(x, y)
	}

	var b strings.Builder
	for y := -quiet; y < n+quiet; y += 2 {
		b.WriteString("\x1b[47;30m") // white bg, black fg — held for the whole row
		for x := -quiet; x < n+quiet; x++ {
			top, bottom := dark(x, y), dark(x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█") // full block
			case top:
				b.WriteString("▀") // upper half
			case bottom:
				b.WriteString("▄") // lower half
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\x1b[0m\n") // reset per row, so a resize cannot bleed colour
	}
	return b.String(), nil
}
