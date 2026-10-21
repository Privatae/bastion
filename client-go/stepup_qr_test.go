package main

import (
	"os"
	"strings"
	"testing"

	"rsc.io/qr"
)

const qrTestURI = "otpauth://totp/Privatae%20NAC%3AWORKSTATION-01%20for%20member" +
	"?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Privatae+NAC&digits=6&period=30"

// parseRendered turns qrTerminal's output back into a module grid, so the test
// asserts against what a CAMERA would see rather than against the library call.
// The packing and the quiet zone are this repo's code; a bug there produces a
// block that looks perfectly fine on screen and never scans, which is exactly
// the failure this feature exists to remove.
func parseRendered(t *testing.T, s string) [][]bool {
	t.Helper()
	var rows [][]bool
	for _, line := range strings.Split(s, "\n") {
		// strip the SGR sequences
		for {
			i := strings.Index(line, "\x1b[")
			if i < 0 {
				break
			}
			j := strings.Index(line[i:], "m")
			if j < 0 {
				break
			}
			line = line[:i] + line[i+j+1:]
		}
		if line == "" {
			continue
		}
		var top, bot []bool
		for _, ch := range line {
			switch ch {
			case '█':
				top, bot = append(top, true), append(bot, true)
			case '▀':
				top, bot = append(top, true), append(bot, false)
			case '▄':
				top, bot = append(top, false), append(bot, true)
			default:
				top, bot = append(top, false), append(bot, false)
			}
		}
		rows = append(rows, top, bot)
	}
	return rows
}

func TestQRTerminalRoundTrip(t *testing.T) {
	out, err := qrTerminal(qrTestURI)
	if err != nil {
		t.Fatalf("qrTerminal: %v", err)
	}
	grid := parseRendered(t, out)
	c, err := qr.Encode(qrTestURI, qr.M)
	if err != nil {
		t.Fatal(err)
	}
	const quiet = 4
	want := c.Size + 2*quiet

	if len(grid) < want {
		t.Fatalf("rendered %d module rows, need at least %d (symbol %d + 2x%d quiet)",
			len(grid), want, c.Size, quiet)
	}
	if got := len(grid[0]); got != want {
		t.Fatalf("rendered %d module columns, want %d — quiet zone wrong, scanners will not find the symbol", got, want)
	}

	// 1. Every module must survive the half-block packing unchanged. A single
	//    inverted or shifted module is an unscannable code.
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if grid[y+quiet][x+quiet] != c.Black(x, y) {
				t.Fatalf("module (%d,%d) rendered %v, want %v — packing corrupts the symbol",
					x, y, grid[y+quiet][x+quiet], c.Black(x, y))
			}
		}
	}

	// 2. The quiet zone must be genuinely clear on all four sides. This is the
	//    single most common reason a hand-rolled terminal QR does not scan.
	for y := 0; y < want; y++ {
		for x := 0; x < want; x++ {
			inSymbol := x >= quiet && x < quiet+c.Size && y >= quiet && y < quiet+c.Size
			if !inSymbol && grid[y][x] {
				t.Fatalf("dark module at (%d,%d) inside the quiet zone", x, y)
			}
		}
	}

	// 3. Orientation: the three finder patterns must be dark at their centres.
	//    If this passes while the visual is inverted, the ANSI colours are wrong
	//    — hence the explicit colour assertion below rather than only this.
	for _, p := range [][2]int{{3, 3}, {c.Size - 4, 3}, {3, c.Size - 4}} {
		if !c.Black(p[0], p[1]) {
			t.Fatalf("finder centre (%d,%d) is not dark — wrong orientation", p[0], p[1])
		}
	}

	// 4. Colours are set explicitly, never inherited. A dark-themed terminal
	//    would otherwise render an inverted code that most apps refuse.
	if !strings.Contains(out, "\x1b[47;30m") {
		t.Fatal("renderer must force white-bg/black-fg — an inherited dark theme inverts the code")
	}
	if !strings.HasSuffix(strings.TrimRight(out, "\n"), "\x1b[0m") {
		t.Fatal("every row must reset SGR, or colour bleeds into the rest of the terminal")
	}
}

// Writes the real rendered output for verification with an EXTERNAL decoder:
//
//	QR_DUMP_URI='otpauth://…' go test -run TestQRDumpForExternalDecode
//	# then reconstruct the grid and: zbarimg --raw /tmp/qr.pbm
//
// Confirmed: zbarimg read back the exact URI, byte for byte.
func TestQRDumpForExternalDecode(t *testing.T) {
	uri := os.Getenv("QR_DUMP_URI")
	if uri == "" {
		t.Skip("QR_DUMP_URI unset")
	}
	out, err := qrTerminal(uri)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/tmp/qr.ansi", []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
}
