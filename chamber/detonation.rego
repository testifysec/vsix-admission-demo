package vsix_detonation

# Input is the command-run attestation from loading the extension under
# cilock's trace. An extension that is only being loaded has no business
# touching your SSH keys, installing persistence, or calling out.

pred := object.get(input, "attestation", input)

procs := object.get(pred, "processes", [])

# No trace, no evidence. A detonation that recorded nothing proved nothing.
deny[msg] {
	count(procs) == 0
	msg := "unreadable evidence: the detonation recorded no traced processes"
}

sensitive(path) { contains(path, "/.ssh/") }
sensitive(path) { contains(path, "/Library/LaunchAgents/") }
sensitive(path) { startswith(path, "/etc/cron") }
sensitive(path) { startswith(path, "/var/spool/cron") }

deny[msg] {
	w := procs[_].fileOps.writes[_]
	sensitive(w.path)
	msg := sprintf("wrote %v while loading", [w.path])
}

deny[msg] {
	some path
	procs[_].openedfiles[path]
	sensitive(path)
	msg := sprintf("opened %v while loading", [path])
}

loopback(addr) { startswith(addr, "127.") }
loopback(addr) { addr == "::1" }

deny[msg] {
	c := procs[_].network.connections[_]
	c.syscall == "connect"
	startswith(c.family, "AF_INET")
	not loopback(c.address)
	msg := sprintf("connected to %v:%v while loading", [c.address, c.port])
}
