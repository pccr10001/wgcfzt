//go:build !windows

package auth

import (
	"fmt"
	"os/exec"
	"runtime"
)

func takeover(dir, exe string) (func() error, error) {
	return nil, fmt.Errorf("temporary protocol takeover is currently supported on Windows; falling back to paste")
}
func Recover(dir string) error          { return nil }
func checkBrowser(browser string) error { return nil }
func openBrowser(browser, url string) error {
	if browser == "firefox" {
		return exec.Command("firefox", "--new-tab", url).Start()
	}
	if runtime.GOOS == "darwin" {
		return exec.Command("open", url).Start()
	}
	return exec.Command("xdg-open", url).Start()
}
