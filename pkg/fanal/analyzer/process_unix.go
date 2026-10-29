//go:build unix

package analyzer

import (
	"os/exec"
	"syscall"
)

// isolateProcessGroup puts cmd in its own process group and cancels by signalling that
// whole group.
//
// exec.CommandContext kills only the direct child. Binary SBOM generators spawn helpers
// -- a decompiler JVM, for one -- that inherit the output pipes, so killing just the
// child leaves those helpers holding the pipes and cmd.Wait blocked well past the
// scan's deadline.
func isolateProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
