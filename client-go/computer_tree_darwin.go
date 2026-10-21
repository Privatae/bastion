//go:build darwin

package main

import "errors"

// macOS: the AX tree through System Events, walked by a fixed JXA script
// (osascript -l JavaScript). Every property read is one Apple Event, so the
// node cap is what keeps a busy window inside the op's timeout. Needs the
// Accessibility permission; the same two error codes computer:windows knows.

const computerTreeKind = "system-events-jxa"

const darwinTreeScript = `
ObjC.import('stdlib');
const targetPid = parseInt($.getenv('PRIVATAE_TARGET_PID'), 10);
const maxNodes = parseInt($.getenv('PRIVATAE_MAX_NODES'), 10);
const se = Application('System Events');
let count = 0, trunc = false;
function str(f) { try { const v = f(); return (v === null || v === undefined) ? '' : String(v); } catch (e) { return ''; } }
function node(el, depth) {
  if (count >= maxNodes || depth > 40) { trunc = true; return null; }
  count++;
  const n = { role: str(() => el.role()).replace(/^AX/, '').toLowerCase() };
  const name = str(() => el.name()); if (name) n.name = name;
  const desc = str(() => el.description()); if (!name && desc) n.name = desc;
  const val = str(() => el.value()); if (val && val.length <= 200) n.value = val;
  try { const p = el.position(), s = el.size(); if (p && s) { n.x = p[0]; n.y = p[1]; n.w = s[0]; n.h = s[1]; } } catch (e) {}
  try { n.enabled = !!el.enabled(); } catch (e) {}
  try { if (el.focused()) n.focused = true; } catch (e) {}
  const kids = [];
  let children = [];
  try { children = el.uiElements(); } catch (e) {}
  for (const c of children) { const k = node(c, depth + 1); if (k) kids.push(k); if (trunc) break; }
  if (kids.length) n.children = kids;
  return n;
}
const procs = se.processes.whose({ unixId: targetPid })();
if (!procs.length) { JSON.stringify({ error: 'no process with pid ' + targetPid }); }
else {
  const p = procs[0];
  const wins = [];
  for (const w of p.windows()) { const t = node(w, 0); if (t) wins.push(t); }
  JSON.stringify({ app: str(() => p.name()), truncated: trunc, windows: wins });
}
`

func readTree(pid, maxNodes int) ([]byte, error) {
	out, err := runFixedEnv(helperEnv(pid, maxNodes), "osascript", "-l", "JavaScript", "-e", darwinTreeScript)
	if err != nil {
		return nil, errors.New(osascriptReason(execFailure(err)))
	}
	return out, nil
}
