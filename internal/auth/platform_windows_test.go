//go:build windows

package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pccr10001/wgcfzt/internal/store"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Opt-in regression for browser protocol launches brokered by Explorer. A normal
// ShellExecute from a test process does not trigger Cobra's Explorer guard.
// This uses a synthetic callback and loopback session, without changing registry.
func TestWindowsExplorerParentCallback(t *testing.T) {
	exe := os.Getenv("WGCFZT_PROTOCOL_TEST_EXE")
	pidText := os.Getenv("WGCFZT_EXPLORER_PID")
	if exe == "" || pidText == "" {
		t.Skip("set WGCFZT_PROTOCOL_TEST_EXE and WGCFZT_EXPLORER_PID for Explorer callback regression")
	}
	pid, e := strconv.ParseUint(pidText, 10, 32)
	if e != nil {
		t.Fatal(e)
	}
	parent, e := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS|windows.PROCESS_DUP_HANDLE, false, uint32(pid))
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(parent)
	dir := t.TempDir()
	jwt := testJWT("example", time.Now().Add(time.Minute))
	callback := "com.cloudflare.warp://example.cloudflareaccess.com/auth?token=" + jwt
	received := make(chan bool, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer explorer-test-nonce" || string(b) != callback {
			http.Error(w, "invalid callback", 400)
			return
		}
		received <- true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer s.Close()
	if e := store.WriteJSON(sessionPath(dir), session{URL: s.URL + "/callback", Nonce: "explorer-test-nonce", Team: "example"}); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "--config-dir", dir, "callback", "--", callback)
	cmd.SysProcAttr = &syscall.SysProcAttr{ParentProcess: syscall.Handle(parent), HideWindow: true, CreationFlags: windows.CREATE_NEW_CONSOLE}
	out, e := cmd.CombinedOutput()
	if strings.Contains(string(out), "This is a command line tool") {
		t.Fatal("Explorer guard blocked the callback")
	}
	if e != nil {
		t.Fatalf("callback helper failed to exit successfully: %v", e)
	}
	select {
	case <-received:
	default:
		t.Fatal("callback helper exited without delivering the token")
	}
}

func TestRegistrySnapshotRestoresValuesAndChildren(t *testing.T) {
	path := fmt.Sprintf(`Software\wgcfzt-tests\restore-%d`, os.Getpid())
	defer removeTree(path)
	k, _, e := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if e != nil {
		t.Fatal(e)
	}
	k.SetStringValue("original", "value")
	k.SetBinaryValue("binary", []byte{0, 1, 255})
	k.Close()
	before, e := snapshot(path)
	if e != nil {
		t.Fatal(e)
	}
	k, _, _ = registry.CreateKey(registry.CURRENT_USER, path+`\new-child`, registry.ALL_ACCESS)
	k.SetStringValue("", "temporary")
	k.Close()
	k, _, _ = registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	k.SetStringValue("original", "changed")
	k.SetStringValue("new-value", "temporary")
	k.Close()
	if e = restoreTree(path, before); e != nil {
		t.Fatal(e)
	}
	after, e := snapshot(path)
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("registry values/subkeys were not exactly restored", e)
	}
}

// Explicit opt-in: exercises the actual Windows URL association with a synthetic
// JWT and a local listener. It never contacts Cloudflare or launches WARP.
func TestWindowsNativeCallbackRoundtrip(t *testing.T) {
	exe := os.Getenv("WGCFZT_PROTOCOL_TEST_EXE")
	dir := os.Getenv("WGCFZT_PROTOCOL_TEST_DIR")
	if exe == "" || dir == "" {
		t.Skip("set WGCFZT_PROTOCOL_TEST_EXE and WGCFZT_PROTOCOL_TEST_DIR to test the real association")
	}
	if !filepath.IsAbs(exe) || !filepath.IsAbs(dir) {
		t.Fatal("integration paths must be absolute")
	}
	if e := store.SecureDir(dir); e != nil {
		t.Fatal(e)
	}
	before, e := snapshot(protocolKey)
	if e != nil {
		t.Fatal(e)
	}
	previous, _ := effectiveCommand()
	restore, e := takeover(dir, exe)
	if e != nil {
		t.Fatal("real takeover failed", e)
	}
	restored := false
	defer func() {
		if !restored {
			if e := restore(); e != nil {
				t.Errorf("RESTORE FAILED; run wgcfzt --config-dir %q recover: %v", dir, e)
			}
		}
	}()
	jwt := testJWT("example", time.Now().Add(time.Minute))
	received := make(chan bool, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer local-test-nonce" || string(b) != "com.cloudflare.warp://example.cloudflareaccess.com/auth?token="+jwt {
			http.Error(w, "invalid", 400)
			return
		}
		received <- true
		w.WriteHeader(204)
	}))
	defer s.Close()
	if e = store.WriteJSON(sessionPath(dir), session{URL: s.URL + "/callback", Nonce: "local-test-nonce", Team: "example"}); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(sessionPath(dir))
	u, _ := windows.UTF16PtrFromString("com.cloudflare.warp://example.cloudflareaccess.com/auth?token=" + jwt)
	if e = windows.ShellExecute(0, nil, u, nil, nil, windows.SW_HIDE); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	select {
	case <-received:
	case <-ctx.Done():
		t.Fatal("native callback was not delivered")
	}
	if e = restore(); e != nil {
		t.Fatal(e)
	}
	restored = true
	after, e := snapshot(protocolKey)
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("original protocol registry tree differs", e)
	}
	current, _ := effectiveCommand()
	if current != previous {
		t.Fatal("effective original handler differs after recovery")
	}
}
