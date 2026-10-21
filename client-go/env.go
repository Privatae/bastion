package main

import "os"

// Environment names carry the product's name. The bastion is the program a
// member installs on their own machine and reads the source of, so every name
// it shows them is PRIVATAE_*.
//
// The lane addresses are read under that name and no other. They are set by
// hand in the bastion's unit environment (the installers write none of them),
// and an unset address means "that lane is absent", so a lane set under any
// other spelling stays off until it is renamed. The changelog says which names
// to set.

// agentTokenEnvNames are the delegation-tag variable names, in preference
// order. This one is read out of ANOTHER process's environment rather than our
// own: each platform reader walks the list with whatever it can use to read
// that process (a /proc file, ps, a Windows handle). The second name is the one
// the host still mints tags under, so an agent launched with one of its tags
// carries it until the host mints the first. A tag under either name marks its
// agent as requested; only a process carrying neither reads as unsanctioned.
var agentTokenEnvNames = []string{"PRIVATAE_AGENT_TOKEN", "SKEMA_AGENT_TOKEN"}

// The lane addresses, resolved in ONE place each. The probe that ADVERTISES a
// lane and the forwarder that SERVES it used to resolve the address separately,
// which let them disagree about which name to read — and that disagreement is
// worse than either lane being absent: the heartbeat reports pii_port and the
// capability while nothing ever listens on the port, so the host dials into a
// closed door instead of skipping a machine it knows has no sterilizer.
// One function per lane, called by both halves, and the disagreement cannot be
// written.
func piiTarget() string { return os.Getenv("PRIVATAE_PII_ADDR") }

func llmTarget() string { return os.Getenv("PRIVATAE_LLM_ADDR") }
