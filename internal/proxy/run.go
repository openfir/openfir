package proxy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Run resolves both paths before changing directory. Hysteria opens the
// relative certificate paths in a profile against its working directory.
func Run(role, config string) error {
	engine, err := exec.LookPath("hysteria")
	if err != nil {
		return fmt.Errorf("install the Hysteria 2 executable as hysteria on PATH: %w", err)
	}
	engine, err = filepath.Abs(engine)
	if err != nil {
		return err
	}
	if _, err := os.Stat(config); err != nil {
		return err
	}
	cmd := exec.Command(engine, role, "--disable-update-check", "--config", filepath.Base(config))
	cmd.Dir = filepath.Dir(config)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return runEngine(cmd)
}
