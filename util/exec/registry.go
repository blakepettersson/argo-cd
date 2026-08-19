package exec

import (
	"os/exec"
	"sync"
	"syscall"
)

// running holds every command between Start and Wait, so that shutdown can signal them. Nothing
// else reaches them: the kubelet signals only the container's init process, which forwards to this
// process alone, and each command sits in its own process group.
var running = struct {
	sync.Mutex
	cmds map[*exec.Cmd]struct{}
}{cmds: map[*exec.Cmd]struct{}{}}

// TerminateRunning signals the process group of every command still running and reports how many
// were signalled. Use SIGTERM on shutdown, so git removes .git/index.lock instead of leaving a
// stale one behind when the container is killed.
func TerminateRunning(sig syscall.Signal) int {
	running.Lock()
	cmds := make([]*exec.Cmd, 0, len(running.cmds))
	for cmd := range running.cmds {
		cmds = append(cmds, cmd)
	}
	running.Unlock()

	// Signalling outside the lock, so a command that exits meanwhile is not blocked from untracking.
	for _, cmd := range cmds {
		_ = SignalProcessGroup(cmd, sig)
	}
	return len(cmds)
}

// trackRunning registers a started command; the returned function unregisters it and must be called
// once Wait has returned.
func trackRunning(cmd *exec.Cmd) (untrack func()) {
	running.Lock()
	running.cmds[cmd] = struct{}{}
	running.Unlock()
	return func() {
		running.Lock()
		delete(running.cmds, cmd)
		running.Unlock()
	}
}
