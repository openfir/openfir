//go:build unix

package proxy

import (
	"os"
	"os/exec"
	"syscall"
)

// Replace the CLI process so signals and the exit status belong to the engine.
func runEngine(cmd *exec.Cmd) error {
	if err := os.Chdir(cmd.Dir); err != nil {
		return err
	}
	return syscall.Exec(cmd.Path, cmd.Args, os.Environ())
}
