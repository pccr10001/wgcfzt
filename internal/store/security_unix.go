//go:build !windows

package store

import (
	"golang.org/x/sys/unix"
	"os"
)

func securePath(path string, dir bool) error {
	mode := os.FileMode(0600)
	if dir {
		mode = 0700
	}
	return os.Chmod(path, mode)
}
func lockFile(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
