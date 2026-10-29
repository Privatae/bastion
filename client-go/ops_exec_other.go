//go:build !linux

package main

// ops_exec_other.go — no sandbox on Windows or macOS in rung 6: every op is
// refused with the sentence, and the beat says so (those machines take the
// bastion's built-in ops until a sandbox exists there).

import (
	"errors"

	"github.com/gorilla/websocket"
)

type opChange struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Size   int64  `json:"size,omitempty"`
	Mode   string `json:"mode,omitempty"`
	Digest string `json:"sha256,omitempty"`
	Diff   string `json:"diff,omitempty"`
	Note   string `json:"note,omitempty"`
}

type opReport struct {
	Mode          string            `json:"mode"`
	Exit          int               `json:"exit"`
	TimedOut      bool              `json:"timed_out,omitempty"`
	TasksCapped   bool              `json:"tasks_capped,omitempty"`
	TasksNote     string            `json:"tasks_note,omitempty"`
	Seconds       float64           `json:"seconds"`
	Output        string            `json:"output"`
	Changes       []opChange        `json:"changes"`
	ChangesSHA256 string            `json:"changes_sha256"`
	Committed     []string          `json:"committed,omitempty"`
	VerifyError   string            `json:"verify_error,omitempty"`
	Verbs         []opVerbResult    `json:"verbs,omitempty"`
	Checks        []opVerbResult    `json:"checks,omitempty"`
	Receipts      []opSignedReceipt `json:"receipts,omitempty"`

	cleanup func()
}

const opSandboxSubcommand = "__op-sandbox"

func opSandboxAvailable() (bool, string) {
	return false, "no op sandbox on this platform yet — this machine takes the bastion's built-in ops only"
}

func opRunSandboxed(_ string, _ *opManifest, _ string, _ string) (*opReport, error) {
	_, why := opSandboxAvailable()
	return nil, errors.New(why)
}

func opCommitUpper(_ *opReport) ([]string, error) {
	return nil, errors.New("no op sandbox on this platform")
}

func opSandboxChildMain(_ string) int { return 125 }

const opSandboxScopeSubcommand = "__op-sandbox-scope"

func opSandboxScopeMain(_ string) int { return 125 }

func opMountsUnder(_ string) []string { return nil }

const (
	opActionSubcommand      = "__op-action"
	opActionChildSubcommand = "__op-action-child"
	opActionProbeSubcommand = "__op-action-probe"
)

func opActionAvailable() (bool, string) {
	return false, "no action-op sandbox on this platform"
}

func opRunAction(_ string, _ *opManifest, _ *opTerms, _, _ string, _ []string, _ *opPlanCtx) (*opReport, error) {
	_, why := opActionAvailable()
	return nil, errors.New(why)
}

// opVerbsReport: no verb runs on this platform.
func opVerbsReport() map[string]any {
	out := map[string]any{}
	for _, verb := range opVerbNames() {
		out[verb] = map[string]any{"ok": false, "why": "no op runs on this platform yet"}
	}
	return out
}

func opActionOuterMain(_ string) int { return 125 }
func opActionChildMain(_ string) int { return 125 }
func opActionProbeMain(_ string) int { return 125 }
func opStartupSweep()                {}

func handlePlanLine(ws *websocket.Conn, _ string, _ []string) {
	opFail(ws, "op_plan_line: no action-op sandbox on this platform")
}

func handlePlanUndo(ws *websocket.Conn, _ string, _ []string) {
	opFail(ws, "op_plan_undo: no action-op sandbox on this platform")
}

func handlePlanStatus(ws *websocket.Conn, _ string, _ []string) {
	opFail(ws, "op_plan_status: no action-op sandbox on this platform")
}
