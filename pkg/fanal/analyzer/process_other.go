//go:build !unix

package analyzer

import "os/exec"

// isolateProcessGroup is a no-op where process groups are not available. Cancellation
// then falls back to exec's default of killing the direct child, with cmd.WaitDelay
// bounding the wait if helper processes keep the output pipes open.
func isolateProcessGroup(_ *exec.Cmd) {}
