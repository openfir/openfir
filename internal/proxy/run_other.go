//go:build !unix

package proxy

import "os/exec"

func runEngine(cmd *exec.Cmd) error {
	return cmd.Run()
}
