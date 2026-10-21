package main

// uidiskmap.go — the disk map page: a squarified treemap of this machine's own
// disk, drawn server-side as SVG.
//
// WHY IT EXISTS. The ask was old-school WinDirStat: turn it on, it maps the
// drive, and you get the 3D colour-coded layout of the drives — integrated
// into this UI. It is the best demo this product has, and the reason is one
// line: every other claim in the pitch becomes legible the moment a person can
// SEE their own machine. "Your AI, on a network you own" — own is a thing you
// have to be able to look at.
//
// WHAT IT READS: names, sizes and modification times. Nothing else, ever. The
// walk and the two tests that hold that line are in diskmap.go; this file only
// draws what that one counted, and it touches no disk at all.
//
// ── NO JAVASCRIPT, AND THE CSP IS WHY ──────────────────────────────────────
//
// Every page in this UI is served with `default-src 'self'; base-uri 'none';
// form-action 'self'` (ui.go renderWith), and default-src covers style-src.
// So there is no 'unsafe-inline' and an inline style="" attribute is BLOCKED —
// app.css:169-173 records the first time that bit somebody here, when an
// inline style="margin-top:1rem" was silently losing to the policy.
//
// A treemap is a thousand rectangles at a thousand different positions, which
// is the single most natural thing in the world to write as inline styles. It
// is written as SVG instead, and that is not a workaround — it is the correct
// tool:
//
//   - x, y, width, height and fill on an <svg:rect> are SVG PRESENTATION
//     ATTRIBUTES, not CSS. style-src does not govern them, so per-rect
//     geometry needs no policy hole at all.
//   - <title> inside a rect is the browser's own native tooltip. No JS, no
//     hover handler, no CSS.
//   - <a href> inside SVG is an ordinary link, so drilling into a folder is a
//     navigation. The browser's BACK BUTTON becomes "drill back out" for free,
//     history works, and a middle-click opens a subtree in a new tab.
//
// The rejected alternative was a client-side layout with d3-hierarchy, which
// is what everyone reaches for. It fails three ways here at once: it is a CDN
// fetch in a privacy product's local UI (ui.go's header forbids it and a
// locked-down box would fail the load), or it is another 90 KB vendored into a
// security binary; it needs the whole tree shipped to the browser as JSON,
// which is 800,000 entries of this machine's filenames serialised into a
// document; and it would need script-src widened. Laying out in Go costs one
// function (dmSquarify) and ships the ANSWER instead of the data.
//
// TestTheMapNeverEmitsInlineStyle asserts the whole point: no style attribute
// and no <style> element ever reaches the page.

import (
	"fmt"
	"html"
	"html/template"
	"math"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ── the drawing budget, measured ────────────────────────────────────────────

// The canvas is a viewBox, not pixels — diskmap.css scales it to the width of
// the page. 1000×620 is close to 16:10 because a squarified treemap's aspect
// ratios are best in a near-square container and worst in a long thin one, and
// a panel-shaped map is what a person recognises as WinDirStat.
const (
	dmCanvasW = 1000.0
	dmCanvasH = 620.0
)

// dmMinCellArea is the smallest rectangle worth drawing, in viewBox units.
// Below it the cell is not emitted at all and is counted into the "too small
// to draw" line, which the page prints with the number of items and their
// total — so the map never quietly omits, it says what it left out.
//
// 9 is a 3×3 cell. Under a 3-unit side the rect is sub-pixel on a 1366-wide
// laptop once the 1000-unit viewBox is scaled down, so it would be paint with
// no information in it — and a page full of those is what makes an SVG
// treemap slow for nothing.
const dmMinCellArea = 9.0

// dmMinRecurseArea is when a directory is opened up rather than drawn as one
// solid block. It is deliberately well above dmMinCellArea: a folder is only
// worth unpacking if its own children can clear dmMinCellArea inside it, and a
// 400-unit box that holds forty children gives each of them ten.
const dmMinRecurseArea = 400.0

// dmMaxDepth is how many levels below the folder being viewed get drawn.
//
// Four, and the reason is legibility rather than cost: past four nestings the
// rectangles are fragments of fragments and a person cannot tell which folder
// any of them belongs to, so the extra levels add paint and remove meaning.
// Measured max depth on this box's whole-machine walk is 19, so this is a real
// cut and the page says so — "click a folder to go deeper" is the interaction
// that replaces it.
const dmMaxDepth = 4

// dmMaxCells is the hard ceiling on rectangles in one picture, and it is a
// PAGE-WEIGHT number rather than a legibility one — dmMinCellArea is what
// decides legibility, and in practice it is also what decides the count.
//
// MEASURED on one build box (TestMeasureARealMap, which is how to redo
// this rather than trust it):
//
//	root    entries    cells   too small    SVG       per cell   drawn in
//	/root   323,963    4,022   30,490       894 KB    227 B      7.1 ms
//	/       800,341    1,229    6,776       284 KB    236 B      3.4 ms
//
// So the real ceiling is dmMinCellArea, and a whole-machine map is SMALLER
// than a home-directory one because at the top level a handful of enormous
// folders take the canvas and everything else falls under three pixels. 6,000
// is roughly half again on the largest measured picture: it is a backstop
// against a pathological tree, not the number that shapes the ordinary one,
// and neither measured root comes near it.
//
// ~900 KB of markup is more than a text page and it is the right trade. It is
// an in-process string over a loopback socket with no network in it, a browser
// lays out 8,000 SVG nodes in well under a frame, and the alternative — a
// chunky map of 500 blocks — loses the exact thing that makes a person
// recognise their own disk.
const dmMaxCells = 6000

// dmBiggestRows is the length of the "biggest things here" table under the
// map. The table exists because the map's small rectangles are unreadable by
// construction: everything big enough to see is already a block you can hover,
// so the list's whole job is to name the top of the ordering exactly. Fifteen
// covers a directory's heavy hitters without becoming a file manager, and the
// page prints how many more there are.
const dmBiggestRows = 15

// ── colour by type, the way WinDirStat does ─────────────────────────────────

// dmKindDef is one colour in the legend. The extension list is the whole rule:
// there is no content sniffing anywhere in this feature, and a NAME is all the
// walk ever read, so the type shown is the type the name claims. That is worth
// being explicit about — a page that said "this is a video" after opening the
// file would be a different product.
type dmKindDef struct {
	Key   string
	Label string
	Fill  string
	Exts  []string
}

// dmKinds, heaviest-first in the order a person scanning the legend cares
// about. Colours are chosen against the panel background (app.css --bg
// #16181d) so every one of them reads as itself on a dark page.
//
// `model` is here and is not a category WinDirStat would have had. It earns
// its place on this product: the host can pull models onto this machine
// (model:pull, modelswap.go) and they are the largest single files most of
// these boxes will ever hold, so "what is that 40 GB" has to have an answer
// better than "other".
var dmKinds = []dmKindDef{
	// `ts` is deliberately NOT here, and it is the one genuinely ambiguous
	// extension in this table: an MPEG transport stream and a TypeScript source
	// share it. It is filed under code because of who runs this — a machine with
	// the Privatae bastion on it is far more likely to hold TypeScript than raw
	// broadcast video, and colouring a node_modules tree as VIDEO would make the
	// map actively misleading in the direction that matters. Caught by the
	// duplicate check in TestTheTypeIsReadOffTheNameAndNothingElse, which exists
	// because dmKindIndex is built in order and the LATER kind silently wins.
	{"video", "Video", "#b45bd1", []string{"mp4", "mkv", "mov", "avi", "wmv", "webm", "m4v", "mpg", "mpeg", "flv", "m2ts"}},
	{"image", "Images", "#4aa3d8", []string{"jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic", "heif", "raw", "cr2", "nef", "arw", "svg", "ico", "psd", "ai"}},
	{"audio", "Audio", "#d8843c", []string{"mp3", "wav", "flac", "aac", "ogg", "oga", "m4a", "wma", "aiff", "opus"}},
	{"model", "Models", "#e0658a", []string{"gguf", "safetensors", "ckpt", "pt", "pth", "onnx", "mlmodel", "tflite", "npz"}},
	// pack/idx are git packfiles and pak is a Chromium resource bundle. They
	// are here because the measurement put them there: 1.7 GB of .pack on this
	// box alone, which as "everything else" tells a user nothing about why
	// their repositories are large.
	{"archive", "Archives", "#d15a52", []string{"zip", "tar", "gz", "tgz", "bz2", "xz", "zst", "7z", "rar", "jar", "war", "iso", "dmg", "pkg", "deb", "rpm", "cab", "msi", "apk", "whl", "pack", "idx", "pak"}},
	{"vmdisk", "Disk images", "#8a6fd1", []string{"vmdk", "vdi", "qcow2", "vhd", "vhdx", "img", "ova", "vbox"}},
	{"document", "Documents", "#52b788", []string{"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "txt", "md", "rtf", "epub", "mobi", "csv", "tsv", "pages", "numbers", "key"}},
	{"code", "Code and config", "#e0c74a", []string{"go", "py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "c", "h", "cc", "cpp", "hpp", "rs", "java", "rb", "php", "cs", "swift", "kt", "scala", "sh", "bash", "ps1", "sql", "html", "htm", "css", "scss", "json", "jsonl", "yaml", "yml", "toml", "ini", "conf", "xml", "proto", "lua", "vim", "el", "map", "mod", "sum", "lock"}},
	{"binary", "Programs", "#7e8aa0", []string{"exe", "dll", "so", "dylib", "bin", "o", "a", "lib", "pdb", "wasm", "class", "pyc", "node", "ko", "sys", "app", "rlib", "rmeta"}},
	{"db", "Databases", "#3fb5b5", []string{"db", "sqlite", "sqlite3", "sqlitedb", "mdb", "accdb", "realm", "ldb", "sst", "myd", "frm", "wal"}},
	{"logtmp", "Logs and temporary", "#6a7482", []string{"log", "tmp", "temp", "cache", "bak", "swp", "swo", "old", "dmp", "crash", "part", "download"}},
	// EVERYTHING ELSE IS THE BIGGEST CATEGORY AND THAT IS NOT A GAP TO CLOSE.
	// Measured on this box: 15.6 GB of the 44.2 GB is files with NO EXTENSION
	// AT ALL — container layers, git objects, caches, binaries with no suffix.
	// A name is the only thing this feature ever reads, so for those files the
	// honest answer is that it does not know, and the way to find out would be
	// to open them. That is the line diskmap.go's header exists to hold, and
	// the legend is where a user meets it: the largest block on their disk is
	// labelled "everything else" because this program did not look inside it.
	{"other", "Everything else", "#4e5563", nil},
}

// dmFolderFill is a folded directory whose contents have no dominant type —
// empty, or unreadable, or genuinely mixed. The darkest thing on the map,
// because "there is something in here and I cannot characterise it" should not
// look like an answer.
const dmFolderFill = "#2b323d"

// dmDominantKind is the type holding the most BYTES under a node, or "" when
// there is nothing under it.
//
// WHY A FOLDED FOLDER IS COLOURED AT ALL. The first cut drew every folded
// directory in dmFolderFill, on the reasoning that a folder is not a file and
// must not be mistakable for one. Rendered against this box it produced a grey
// desert: a map of /root came out as a few thousand near-identical dark blocks
// with a bright corner, because at four levels deep almost everything is a
// folded folder. That is honest and it is unreadable, and an unreadable map is
// not a more honest one — it just says less.
//
// So a folded folder takes the colour of what is inside it, which is both
// prettier and MORE informative: a block of video reads purple whether the
// video is one file or four hundred, and that is exactly what WinDirStat's
// picture conveys by drawing every file individually. The <title> still says
// "folder", and the size beside it is the roll-up, so nothing about the block
// claims to be a single file.
//
// COST IS O(n) OVER THE WHOLE MAP, not O(n) per folded block: once a directory
// is folded the renderer does not recurse into it, so the subtrees this walks
// are disjoint and their sizes sum to the tree. Measured by
// TestMeasureARealMap on a whole-machine map of 801,782 nodes, drawing the
// whole picture went from 3.4 ms to 25.9 ms when this was added — one extra
// pass over the tree, paid once per render, and invisible beside the 1.9 s the
// walk itself takes.
func dmDominantKind(res *dmResult, at int32) string {
	bytes := map[string]int64{}
	stack := []int32{at}
	for len(stack) > 0 {
		i := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for c := res.Nodes[i].FirstChild; c >= 0; c = res.Nodes[c].NextSibling {
			n := &res.Nodes[c]
			if n.Dir {
				stack = append(stack, c)
				continue
			}
			bytes[dmKindOf(n.Name)] += n.Size
		}
	}
	best, bestN := "", int64(0)
	// dmKinds order breaks a tie, so the same folder is always the same colour
	// rather than whichever key the map handed back first.
	for _, kd := range dmKinds {
		if bytes[kd.Key] > bestN {
			best, bestN = kd.Key, bytes[kd.Key]
		}
	}
	return best
}

// dmKindIndex maps an extension to its kind, built once.
var dmKindIndex = func() map[string]string {
	m := map[string]string{}
	for _, k := range dmKinds {
		for _, e := range k.Exts {
			m[e] = k.Key
		}
	}
	return m
}()

var dmKindByKey = func() map[string]dmKindDef {
	m := map[string]dmKindDef{}
	for _, k := range dmKinds {
		m[k.Key] = k
	}
	return m
}()

// dmKindOf reads the type off the NAME and nothing else.
//
// A dotfile with no other dot ( .bashrc, .env ) has no extension — the leading
// dot is not one — and lands in "everything else". That is right rather than a
// gap: guessing that .env is config would be inventing a fact about a file
// this code deliberately never opened.
func dmKindOf(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 || i == len(name)-1 {
		return "other"
	}
	if k, ok := dmKindIndex[strings.ToLower(name[i+1:])]; ok {
		return k
	}
	return "other"
}

func dmFillOf(kind string) string {
	if k, ok := dmKindByKey[kind]; ok {
		return k.Fill
	}
	return dmKindByKey["other"].Fill
}

// ── the squarified layout ───────────────────────────────────────────────────

type dmRect struct{ X, Y, W, H float64 }

func (r dmRect) area() float64 { return r.W * r.H }

// dmSquarify is Bruls, Huizing and van Wijk's squarified treemap (2000): lay
// the values out in rows along the shortest side of the remaining rectangle,
// growing each row for exactly as long as doing so IMPROVES the worst aspect
// ratio in it.
//
// Why squarified rather than the obvious slice-and-dice, which is ten lines:
// slice-and-dice gives every cell the full height of its parent, so a folder
// with two hundred children is two hundred vertical hairlines. Nothing is
// hoverable, nothing is clickable, and the picture carries no shape. Aspect
// ratio is the whole reason a treemap is legible, and it is the only thing
// this algorithm optimises.
//
// vals MUST be descending — dmChildren sorts by size, which is where they come
// from — because the greedy row-growing is only near-optimal on sorted input.
// Zero and negative values get an empty rectangle and take no space: a 0-byte
// file has no area, and dividing by it is how this returns NaN.
func dmSquarify(vals []float64, r dmRect) []dmRect {
	out := make([]dmRect, len(vals))
	if len(vals) == 0 || r.W <= 0 || r.H <= 0 {
		return out
	}
	total := 0.0
	for _, v := range vals {
		if v > 0 {
			total += v
		}
	}
	if total <= 0 {
		return out
	}
	scale := r.area() / total
	areas := make([]float64, len(vals))
	for i, v := range vals {
		if v > 0 {
			areas[i] = v * scale
		}
	}
	cur := r
	i := 0
	for i < len(areas) {
		if cur.W <= 0 || cur.H <= 0 {
			break
		}
		if areas[i] <= 0 {
			// Everything from here on is zero (the input is descending), so
			// there is nothing left with any area to place.
			break
		}
		side := math.Min(cur.W, cur.H)
		sum := areas[i]
		j := i + 1
		best := dmWorstRatio(areas[i:j], sum, side)
		for j < len(areas) && areas[j] > 0 {
			s2 := sum + areas[j]
			w2 := dmWorstRatio(areas[i:j+1], s2, side)
			if w2 > best {
				break
			}
			best, sum, j = w2, s2, j+1
		}
		cur = dmLayRow(areas[i:j], sum, cur, out[i:j])
		i = j
	}
	return out
}

// dmWorstRatio is the worst aspect ratio a row would have if it were laid out
// now: the row's thickness is sum/side, so the largest member is the flattest
// and the smallest is the thinnest, and one of those two is always the worst.
func dmWorstRatio(row []float64, sum, side float64) float64 {
	if len(row) == 0 || sum <= 0 || side <= 0 {
		return math.Inf(1)
	}
	mx, mn := row[0], row[0]
	for _, a := range row {
		if a > mx {
			mx = a
		}
		if a < mn {
			mn = a
		}
	}
	if mn <= 0 {
		return math.Inf(1)
	}
	s2, side2 := sum*sum, side*side
	return math.Max(side2*mx/s2, s2/(side2*mn))
}

// dmLayRow places one finished row and returns what is left of the rectangle.
func dmLayRow(areas []float64, sum float64, cur dmRect, out []dmRect) dmRect {
	if cur.H <= cur.W {
		// The height is the shortest side, so the row is a COLUMN down the
		// left edge and the remainder is everything to its right.
		w := sum / cur.H
		y := cur.Y
		for k, a := range areas {
			h := a / w
			out[k] = dmRect{X: cur.X, Y: y, W: w, H: h}
			y += h
		}
		return dmRect{X: cur.X + w, Y: cur.Y, W: cur.W - w, H: cur.H}
	}
	h := sum / cur.W
	x := cur.X
	for k, a := range areas {
		w := a / h
		out[k] = dmRect{X: x, Y: cur.Y, W: w, H: h}
		x += w
	}
	return dmRect{X: cur.X, Y: cur.Y + h, W: cur.W, H: cur.H - h}
}

// ── drawing ─────────────────────────────────────────────────────────────────

// dmDraw walks the tree and the layout together, emitting SVG.
type dmDraw struct {
	res *dmResult
	sb  strings.Builder
	// cells is what was actually drawn; tiny/tinyBytes is what was not, and
	// the page prints both because the second number is the honesty.
	cells     int
	tiny      int
	tinyBytes int64
	// budget exhausted: dmMaxCells was reached and the picture is incomplete
	// for a reason that is this renderer's and not the disk's.
	overflow bool
}

// dmNumber formats a coordinate. One decimal place: integers visibly misalign
// adjacent cells at small sizes (two rects rounding the same edge in opposite
// directions leave a gap or overlap), and a second decimal adds bytes to every
// attribute of every cell for precision below a tenth of a viewBox unit, which
// is a fiftieth of a pixel on screen.
func dmNumber(f float64) string { return strconv.FormatFloat(f, 'f', 1, 64) }

func dmEsc(s string) string { return html.EscapeString(s) }

// draw emits one node's children into r, recursing while the rectangles stay
// big enough to mean anything.
func (d *dmDraw) draw(node int32, r dmRect, depth int) {
	if depth > dmMaxDepth || r.W <= 0 || r.H <= 0 {
		return
	}
	kids := d.res.dmChildren(node)
	if len(kids) == 0 {
		return
	}
	vals := make([]float64, len(kids))
	for i, k := range kids {
		vals[i] = float64(d.res.Nodes[k].Size)
	}
	rects := dmSquarify(vals, r)
	for i, k := range kids {
		rect := rects[i]
		n := &d.res.Nodes[k]
		if rect.area() < dmMinCellArea {
			// Not drawn, but COUNTED. Every byte under here is still inside
			// its parent's rectangle — the map's totals stay exact and only
			// the detail is gone, which is the difference between a cap and a
			// lie.
			d.tiny++
			d.tinyBytes += n.Size
			continue
		}
		if d.cells >= dmMaxCells {
			d.overflow = true
			return
		}
		if n.Dir && depth < dmMaxDepth && rect.area() >= dmMinRecurseArea {
			// A folder big enough to open: draw it as its own dark ground and
			// then lay its children on top, inset by one unit so the boundary
			// between two folders is visible as a hairline of background.
			d.cell(k, rect, dmFolderFill, true)
			in := dmRect{X: rect.X + 1, Y: rect.Y + 1, W: rect.W - 2, H: rect.H - 2}
			if in.W > 0 && in.H > 0 {
				d.draw(k, in, depth+1)
			}
			continue
		}
		fill := dmFolderFill
		switch {
		case !n.Dir:
			fill = dmFillOf(dmKindOf(n.Name))
		default:
			// Folded: colour it by what is in it. See dmDominantKind.
			if kind := dmDominantKind(d.res, k); kind != "" {
				fill = dmFillOf(kind)
			}
		}
		d.cell(k, rect, fill, n.Dir)
	}
}

// cell emits one rectangle, its tooltip, and — where it is big enough for the
// effect to be visible — the cushion overlay that makes the map look like
// WinDirStat rather than like a bar chart.
//
// THE CUSHION IS ONE GRADIENT IN <defs>, REUSED. WinDirStat's look is Van
// Wijk's cushion shading, which is a per-pixel surface normal and is not
// something SVG does cheaply. What IS cheap is a second rect over the first
// carrying a shared linearGradient in objectBoundingBox units, which is the
// SVG default — so one definition scales itself to every cell and gives each
// block a light top-left and a dark bottom-right. It costs one <defs> entry
// and 44 bytes per cell, and it is skipped below dmCushionFrom because at
// three pixels across there is nothing for a highlight to fall on.
func (d *dmDraw) cell(node int32, r dmRect, fill string, isDir bool) {
	d.cells++
	n := &d.res.Nodes[node]
	x, y, w, h := dmNumber(r.X), dmNumber(r.Y), dmNumber(r.W), dmNumber(r.H)

	// A folder is a link and a file is not, because there is nowhere for a
	// file to lead. The <a> wrapper is also the largest per-cell cost, so
	// spending it only where it does something is most of why a whole-machine
	// map fits in one page.
	if isDir {
		d.sb.WriteString(`<a href="/diskmap?p=` +
			dmEsc(url.QueryEscape(d.res.dmPath(node))) + `">`)
	}
	d.sb.WriteString(`<rect x="` + x + `" y="` + y + `" width="` + w +
		`" height="` + h + `" fill="` + fill + `">`)
	d.sb.WriteString(`<title>` + dmEsc(n.Name) + " · " + dmEsc(dmBytes(n.Size)))
	if isDir {
		d.sb.WriteString(" · folder")
	}
	if n.Mtime > 0 {
		d.sb.WriteString(" · " + dmEsc(time.Unix(n.Mtime, 0).Local().Format("2 Jan 2006")))
	}
	d.sb.WriteString(`</title></rect>`)
	if r.area() >= dmCushionFrom {
		d.sb.WriteString(`<rect x="` + x + `" y="` + y + `" width="` + w +
			`" height="` + h + `" fill="url(#dmcushion)"/>`)
	}
	if isDir {
		d.sb.WriteString(`</a>`)
	}
}

// dmCushionFrom is the smallest cell that gets the 3D overlay. 36 units is a
// 6×6 block; below that the highlight and the shadow are each under three
// units wide and the eye reads the whole cell as one flat muddier colour — so
// the overlay would cost bytes to make the map LESS legible, not more.
const dmCushionFrom = 36.0

// dmSVG renders the map of one node.
func dmSVG(res *dmResult, node int32) (svg string, cells, tiny int, tinyBytes int64, overflow bool) {
	d := &dmDraw{res: res}
	d.sb.WriteString(`<svg class="dm-svg" viewBox="0 0 ` + dmNumber(dmCanvasW) + " " +
		dmNumber(dmCanvasH) + `" xmlns="http://www.w3.org/2000/svg" role="img" ` +
		`aria-label="A map of this folder: every rectangle is a file or folder, sized by how much space it takes.">`)
	// One gradient, reused by every cell. x2/y2 put the light source at the
	// top-left, which is the convention every desktop treemap uses and the one
	// a person's eye already expects.
	d.sb.WriteString(`<defs><linearGradient id="dmcushion" x1="0" y1="0" x2="0.4" y2="1">` +
		`<stop offset="0" stop-color="#ffffff" stop-opacity="0.28"/>` +
		`<stop offset="0.45" stop-color="#ffffff" stop-opacity="0"/>` +
		`<stop offset="1" stop-color="#000000" stop-opacity="0.34"/>` +
		`</linearGradient></defs>`)
	d.draw(node, dmRect{X: 0, Y: 0, W: dmCanvasW, H: dmCanvasH}, 1)
	d.sb.WriteString(`</svg>`)
	return d.sb.String(), d.cells, d.tiny, d.tinyBytes, d.overflow
}

// ── bytes in words ──────────────────────────────────────────────────────────

// dmBytes spells a size the way this machine already spells one.
//
// It DELEGATES to modelBytesWords (modelswap.go:1060) from a megabyte up,
// rather than writing a second formatter, so the number a user reads on this
// page and the number they read when approving a model download are spelled
// identically. The kilobyte tier below it is the one thing this page needs and
// that one does not: a disk map is mostly small files, and "487424 bytes" on
// every row is technically the same fact and unreadable.
func dmBytes(n int64) string {
	if n >= 1<<20 {
		return modelBytesWords(n)
	}
	if n >= 1<<10 {
		return fmt.Sprintf("%.0f KB", float64(n)/float64(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}

// dmAgo says how old something is in the words a person uses for it.
func dmAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < 2*time.Minute:
		return "a minute ago"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 2*time.Hour:
		return "an hour ago"
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

// dmSpan says how long something took or has been running.
func dmSpan(d time.Duration) string {
	if d < time.Minute {
		if n := int(d.Seconds() + 0.5); n == 1 {
			return "1 second"
		}
		return fmt.Sprintf("%.0f seconds", d.Seconds())
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm %02ds", m, s)
}

// ── what the page shows ─────────────────────────────────────────────────────

type uiDiskCrumb struct {
	Name string
	Path string
	Here bool
}

type uiDiskRow struct {
	Name     string
	Path     string
	Size     string
	Bytes    int64
	Share    int // whole percent of the folder being viewed
	Dir      bool
	Kind     string
	Fill     string
	Modified string
}

type uiDiskLegendRow struct {
	Label string
	Fill  string
	Size  string
	Items int64
}

type uiDiskRoot struct {
	Path string
	Size string
}

type uiDiskMap struct {
	Version   string
	CheckedAt string

	// Scanning and what it has counted so far.
	Scanning bool
	Running  string
	SeenAt   string
	Entries  int64
	SeenSize string

	// The map itself.
	HaveMap  bool
	TakenAgo string
	TookFor  string
	Stale    bool

	Roots     []uiDiskRoot
	RootNotes []string

	// Scope is what this map covers — "home" or "machine" — and ScopeWords is
	// the same thing in the words the page says out loud. Both are carried
	// because the template needs to COMPARE (to decide which offer to make) and
	// to PRINT, and doing the comparison on the printed words is how a copy
	// edit silently changes behaviour.
	Scope      string
	ScopeWords string
	// MachineRoots is what a whole-machine request would walk. Shown BEFORE
	// that request is made, never after.
	MachineRoots []string

	Path     string
	Crumbs   []uiDiskCrumb
	Total    string
	Items    int
	NotFound bool
	// Want is the path the person ASKED for, which is not always one this map
	// can resolve yet. It exists because a re-scan starts with an empty map, so
	// Path is unset, so Query was empty, so the fragment's own poll came back
	// with no ?p= and dropped the user at the root the moment the scan finished.
	// Path answers "where are you"; Want answers "where
	// were you going", and only the poll needs the second.
	Want string

	// SVG is template.HTML because it IS markup this file built, and every
	// value that came off the disk went through dmEsc on the way in. That is
	// the whole bargain of the type: it turns escaping from something the
	// template does into something this file is responsible for, so
	// TestAFilenameCannotInjectMarkupIntoTheMap exists to hold the other end
	// of it with a file literally named `<script>`.
	SVG      template.HTML
	Cells    int
	Tiny     int
	TinySize string
	Overflow bool

	Legend  []uiDiskLegendRow
	Biggest []uiDiskRow
	MoreRow int

	// The accounting: everything this map is NOT.
	Capped      bool
	CappedAt    string
	Cancelled   bool
	Denied      int64
	DeniedPaths []string
	Crossings   []string
	Skipped     []string

	Flash      string
	FlashClass string
}

// collectDiskMap builds the page for one path. It reads the held map and
// NEVER the filesystem: a `p=` that names something this scan did not see
// resolves to nothing and is refused in words, because the only paths that
// exist here are the ones already in the tree (diskmap.go dmFind).
func collectDiskMap(path string) uiDiskMap {
	// Want is set FIRST, before any early return. It is a property of the
	// REQUEST, not of the map — and the early return below (no scan has
	// finished yet) is exactly the case that needs it, because that is the view
	// whose poll has to come back to the same folder when the walk lands.
	v := uiDiskMap{Version: clientVersion, CheckedAt: uiNow().Format("15:04:05"),
		Want: strings.TrimSpace(path)}

	snap := diskMap.dmView()

	// SCOPE FIRST, because everything else on this page is read in the light of
	// it. The notes belong to the scope being described, so they are resolved
	// for the same one rather than for whatever the default happens to be.
	v.Scope = string(snap.Scope)
	if v.Scope == "" {
		v.Scope = string(dmScopeHome)
	}
	v.ScopeWords = dmScope(v.Scope).words()
	_, rootNotes := diskMap.roots(dmScope(v.Scope))
	v.RootNotes = rootNotes

	// What the whole-machine request would cover, NAMED, so the button that
	// starts it can say so before it is pressed rather than after. A single
	// click has to say what it covers or it is blind — the same reason the
	// fleet-update confirmation lists its machines.
	machineRoots, _ := diskMap.roots(dmScopeMachine)
	v.MachineRoots = machineRoots

	if snap.Running {
		v.Scanning = true
		v.Running = dmSpan(snap.Since)
		v.SeenAt, v.Entries = snap.Prog.At, snap.Prog.Entries
		v.SeenSize = dmBytes(snap.Prog.Bytes)
	}
	res := snap.Res
	if res == nil || len(res.Nodes) == 0 {
		return v
	}

	v.HaveMap = true
	v.TakenAgo, v.TookFor = dmAgo(uiNow().Sub(res.TakenAt)), dmSpan(res.Elapsed)
	// Decided in dmView, under the same lock that read the map, because the
	// window it is compared against lives on the state.
	v.Stale = snap.Stale
	v.Capped, v.CappedAt, v.Cancelled = res.Capped, res.CappedAt, res.Cancelled
	v.Denied, v.DeniedPaths = res.Denied, res.DeniedPaths
	v.Crossings, v.Skipped = res.Crossings, res.Skipped
	for _, ri := range res.Roots {
		v.Roots = append(v.Roots, uiDiskRoot{
			Path: res.Nodes[ri].Name, Size: dmBytes(res.Nodes[ri].Size)})
	}

	at := int32(-1)
	if strings.TrimSpace(path) != "" {
		if at = res.dmFind(path); at < 0 {
			// Said rather than silently redirected to the root. A path that
			// is not in the map is usually a map taken before that folder
			// existed, and "I typed it and got the root" teaches nothing.
			v.NotFound = true
		}
	}
	if at < 0 {
		if len(res.Roots) == 0 {
			return v
		}
		at = res.Roots[0]
	}
	if !res.Nodes[at].Dir {
		// A file has no inside. Show its parent, which is what the person
		// meant if they got here by hand-editing a URL.
		if p := res.Nodes[at].Parent; p >= 0 {
			at = p
		}
	}

	v.Path = res.dmPath(at)
	v.Crumbs = dmCrumbs(res, at)
	v.Total = dmBytes(res.Nodes[at].Size)

	svg, cells, tiny, tinyBytes, overflow := dmSVG(res, at)
	v.SVG, v.Cells, v.Tiny, v.Overflow = template.HTML(svg), cells, tiny, overflow
	v.TinySize = dmBytes(tinyBytes)

	kids := res.dmChildren(at)
	v.Items = len(kids)
	total := res.Nodes[at].Size
	for i, k := range kids {
		if i >= dmBiggestRows {
			v.MoreRow = len(kids) - dmBiggestRows
			break
		}
		n := &res.Nodes[k]
		row := uiDiskRow{
			Name: n.Name, Path: res.dmPath(k), Size: dmBytes(n.Size),
			Bytes: n.Size, Dir: n.Dir,
		}
		if total > 0 {
			row.Share = int(float64(n.Size) * 100 / float64(total))
		}
		if n.Dir {
			// THE SAME COLOUR THE MAP GAVE IT, from the same function. A folder
			// drawn purple in the picture and grey in the table two inches
			// below it is a view disagreeing with itself, which is the failure
			// uigiven.go:38-41 names: a view that re-derives its subject drifts
			// from it. The kind says what is inside for the same reason — the
			// colour is already making that claim, so the words may as well.
			row.Kind, row.Fill = "folder", dmFolderFill
			if k := dmDominantKind(res, kids[i]); k != "" {
				row.Fill = dmFillOf(k)
				if kd, ok := dmKindByKey[k]; ok {
					row.Kind = "folder — mostly " + strings.ToLower(kd.Label)
				}
			}
		} else {
			row.Kind = dmKindOf(n.Name)
			row.Fill = dmFillOf(row.Kind)
			if kd, ok := dmKindByKey[row.Kind]; ok {
				row.Kind = kd.Label
			}
		}
		if n.Mtime > 0 {
			row.Modified = time.Unix(n.Mtime, 0).Local().Format("2 Jan 2006")
		}
		v.Biggest = append(v.Biggest, row)
	}
	v.Legend = dmLegend(res, at)
	return v
}

// dmCrumbs is the path from the root down to here, each step a link.
func dmCrumbs(res *dmResult, at int32) []uiDiskCrumb {
	var chain []int32
	for i := at; i >= 0; {
		chain = append(chain, i)
		if res.Nodes[i].Root {
			break
		}
		i = res.Nodes[i].Parent
	}
	out := make([]uiDiskCrumb, 0, len(chain))
	for i := len(chain) - 1; i >= 0; i-- {
		out = append(out, uiDiskCrumb{
			Name: res.Nodes[chain[i]].Name,
			Path: res.dmPath(chain[i]),
			Here: chain[i] == at,
		})
	}
	return out
}

// dmLegend totals the WHOLE subtree by type, not only the cells that were
// drawn.
//
// That distinction is the legend's entire value. A legend built from the
// picture would say "video 2 GB" about a folder holding 40 GB of video in
// files too small to draw individually, and it would be wrong in the direction
// that matters — the user is here to find out where the space went, and the
// space is in the part the picture could not show.
//
// An explicit stack rather than recursion, for the same reason dmRollUp is a
// loop: the measured tree is 800,000 nodes and 19 levels deep.
func dmLegend(res *dmResult, at int32) []uiDiskLegendRow {
	bytes := map[string]int64{}
	items := map[string]int64{}
	stack := []int32{at}
	for len(stack) > 0 {
		i := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for c := res.Nodes[i].FirstChild; c >= 0; c = res.Nodes[c].NextSibling {
			n := &res.Nodes[c]
			if n.Dir {
				stack = append(stack, c)
				continue
			}
			k := dmKindOf(n.Name)
			bytes[k] += n.Size
			items[k]++
		}
	}
	var out []uiDiskLegendRow
	for _, kd := range dmKinds {
		if items[kd.Key] == 0 {
			continue
		}
		out = append(out, uiDiskLegendRow{
			Label: kd.Label, Fill: kd.Fill,
			Size: dmBytes(bytes[kd.Key]), Items: items[kd.Key],
		})
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Items > out[b].Items })
	sort.SliceStable(out, func(a, b int) bool {
		return dmLegendBytes(bytes, out[a].Label) > dmLegendBytes(bytes, out[b].Label)
	})
	return out
}

func dmLegendBytes(bytes map[string]int64, label string) int64 {
	for _, kd := range dmKinds {
		if kd.Label == label {
			return bytes[kd.Key]
		}
	}
	return 0
}

// ── the routes ──────────────────────────────────────────────────────────────

// diskMapRoutes registers the page.
//
// Every one goes through u.guarded, which runs the rebinding Host check before
// it looks at a cookie (uiauth.go:258) and the Origin check on anything that
// is not a read. THE METHOD CHECK IS INSIDE EACH HANDLER and not in the mux
// pattern, for the reason uisetup.go:189-193 already gives: Go's method
// patterns would answer a rebound host with 405 before uiRequestAllowed ran,
// and the rebinding wall has to be the outermost thing on every route.
//
// A FILE LISTING IS SENSITIVE — filenames alone say what a person works on,
// who they bank with and what they are ill with. Nothing here may reach an
// unauthenticated caller, which is why all four are in
// TestNothingAboutTheMachineLeaksWithoutASession as well as in the rebinding
// walk.
func (u *uiServer) diskMapRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/diskmap", u.guarded(u.diskMapPage))
	mux.HandleFunc("/fragments/diskmap", u.guarded(u.diskMapFragment))
	mux.HandleFunc("/diskmap/scan", u.guarded(u.diskMapScan))
	mux.HandleFunc("/diskmap/stop", u.guarded(u.diskMapStop))
}

func (u *uiServer) diskMapPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	u.renderDiskMap(w, "diskmap.html", r.URL.Query().Get("p"), "", "")
}

func (u *uiServer) diskMapFragment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	u.renderDiskMap(w, "diskmap", r.URL.Query().Get("p"), "", "")
}

// diskMapScan starts the walk. POST, so the Origin check applies: it is the
// one thing on this page that makes the machine do work, and a <img src> that
// could start a full-disk walk is a denial of service written by accident.
func (u *uiServer) diskMapScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// The SMALLER walk is the default, and an unrecognised value resolves to it
	// rather than erroring: a typo must never widen what gets read.
	scope := dmScopeOf(r.FormValue("scope"))
	if diskMap.dmStart(scope) {
		// KEEP WHERE THEY WERE STANDING. This passed "" and dropped the user at
		// the root of the disk every time they re-scanned from inside a folder.
		// The lookup below already handles a path the new
		// map does not contain — it says NotFound rather than redirecting — so
		// carrying it is safe even mid-walk.
		u.renderDiskMap(w, "diskmap", r.FormValue("p"),
			"Mapping "+scope.words()+". It keeps going if you leave this page.", "ok")
		return
	}
	u.renderDiskMap(w, "diskmap", r.FormValue("p"),
		"A scan is already running — this is it.", "warn")
}

func (u *uiServer) diskMapStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	diskMap.dmStop()
	u.renderDiskMap(w, "diskmap", r.FormValue("p"),
		"Stopped. What it had already counted is kept and is labelled as partial.", "warn")
}

// renderDiskMap sets the SAME four headers renderWith does (ui.go:429-434) and
// not one fewer. They are repeated rather than shared for the reason
// uigiven.go:513-518 gives — renderWith is typed to uiStatus and widening it
// belongs to whoever owns that file — and the duplication is made safe by
// TestTheDiskMapCarriesTheSameHeadersAsTheStatusPage, which compares the two
// responses header by header.
func (u *uiServer) renderDiskMap(w http.ResponseWriter, name, path, flash, class string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	v := collectDiskMap(path)
	v.Flash, v.FlashClass = flash, class
	if err := u.tpl.ExecuteTemplate(w, name, v); err != nil {
		uilogf("render %s: %v\n", name, err)
	}
}

// Query is the current path as a query string, so the fragment's poll comes
// back to the folder the person is looking at instead of jumping to the root
// under them. EXPORTED because html/template will only call an exported
// method, which is also why it is a method rather than a field: a field would
// have to be filled on every one of the five paths that build this view.
func (v uiDiskMap) Query() string {
	// Want first: during a scan the map is empty and Path is unset, and that is
	// exactly when the poll must still carry where the person was standing.
	p := v.Path
	if p == "" {
		p = v.Want
	}
	if p == "" {
		return ""
	}
	return "?p=" + url.QueryEscape(p)
}

// Leaf is the last element of the viewed path, used as the page's heading.
func (v uiDiskMap) Leaf() string {
	if v.Path == "" {
		return ""
	}
	if b := filepath.Base(v.Path); b != "" && b != "." {
		return b
	}
	return v.Path
}
