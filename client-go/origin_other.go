//go:build !linux && !darwin && !windows

package main

// No enumerator, no facts: every origin reads `unknown` with the evidence
// line saying why, and no scheduler inventory travels.

func procFactsReader() func(int) (procFacts, bool) {
	return func(int) (procFacts, bool) { return procFacts{}, false }
}

func originExtras() originExtra { return originExtra{} }

func platformSchedulers() ([]schedEntry, []string, bool) { return nil, nil, false }
