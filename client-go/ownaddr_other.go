//go:build !linux

package main

// No route lookup is built for this platform: ownRouteLookup stays nil and
// ownDestination (ownaddr.go) compares against the interface addresses only.
// An address delivered locally through a route alone (AnyIP) is not seen here,
// nor a container's or VM's address on a network made on this machine.
