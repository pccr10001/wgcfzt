package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testJWT(team string, exp time.Time) string {
	b, _ := json.Marshal(map[string]any{"iss": "https://" + team + ".cloudflareaccess.com", "exp": exp.Unix()})
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(b) + ".test-signature"
}
func TestParseToken(t *testing.T) {
	jwt := testJWT("example", time.Now().Add(time.Hour))
	for _, s := range []string{jwt, "com.cloudflare.warp://example.cloudflareaccess.com/auth?token=" + jwt} {
		got, e := ParseToken(s, "example")
		if e != nil || got != jwt {
			t.Fatal("valid input rejected", e)
		}
	}
	for _, s := range []string{"", testJWT("other", time.Now().Add(time.Hour)), testJWT("example", time.Now().Add(-time.Hour)), "com.cloudflare.warp://other.cloudflareaccess.com/auth?token=" + jwt, "com.cloudflare.warp://example.cloudflareaccess.com/wrong?token=" + jwt} {
		if _, e := ParseToken(s, "example"); e == nil {
			t.Fatal("accepted invalid input")
		}
	}
}
func hooks(t *testing.T, install func(string, string) (func() error, error), browser func(string, string) error) {
	oldInstall, oldBrowser := installHandler, launchBrowser
	installHandler, launchBrowser = install, browser
	t.Cleanup(func() { installHandler, launchBrowser = oldInstall, oldBrowser })
}
func TestLoginDeliversThenRestoresBeforeReturning(t *testing.T) {
	dir := t.TempDir()
	restored := false
	jwt := testJWT("example", time.Now().Add(time.Hour))
	hooks(t, func(string, string) (func() error, error) { return func() error { restored = true; return nil }, nil }, func(string, string) error {
		return Deliver(context.Background(), dir, "com.cloudflare.warp://example.cloudflareaccess.com/auth?token="+jwt)
	})
	got, e := Login(context.Background(), Options{Team: "example", Dir: dir, Timeout: time.Second, Out: io.Discard, In: strings.NewReader("")})
	if e != nil || got != jwt || !restored {
		t.Fatal("login must deliver and restore", e)
	}
	if _, e = os.Stat(sessionPath(dir)); !os.IsNotExist(e) {
		t.Fatal("callback session retained")
	}
}
func TestLoginTimeoutAndRestoreFailure(t *testing.T) {
	for _, failRestore := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout", true: "restore-failure"}[failRestore], func(t *testing.T) {
			dir := t.TempDir()
			restored := false
			hooks(t, func(string, string) (func() error, error) {
				return func() error {
					restored = true
					if failRestore {
						return errors.New("cannot restore")
					}
					return nil
				}, nil
			}, func(string, string) error {
				if failRestore {
					return Deliver(context.Background(), dir, "com.cloudflare.warp://example.cloudflareaccess.com/auth?token="+testJWT("example", time.Now().Add(time.Hour)))
				}
				return nil
			})
			got, e := Login(context.Background(), Options{Team: "example", Dir: dir, Timeout: 20 * time.Millisecond, Out: io.Discard, In: strings.NewReader("")})
			if e == nil || got != "" || !restored {
				t.Fatal("must not return token after timeout/restoration failure")
			}
		})
	}
}
func TestFailedTakeoverFallsBackToPaste(t *testing.T) {
	jwt := testJWT("example", time.Now().Add(time.Hour))
	hooks(t, func(string, string) (func() error, error) { return nil, errors.New("protected UserChoice") }, func(string, string) error { t.Fatal("unexpected browser launch"); return nil })
	got, e := Login(context.Background(), Options{Team: "example", Dir: t.TempDir(), Timeout: time.Second, Out: io.Discard, In: strings.NewReader(jwt + "\n")})
	if e != nil || got != jwt {
		t.Fatal(e)
	}
}
func TestStaleBackupDoesNotProceedToRegistration(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "protocol-backup.json"), []byte("{}"), 0600)
	hooks(t, func(string, string) (func() error, error) { return nil, ErrRecoveryRequired }, func(string, string) error { return nil })
	got, e := Login(context.Background(), Options{Team: "example", Dir: dir, Timeout: time.Second, Out: io.Discard, In: strings.NewReader(testJWT("example", time.Now().Add(time.Hour)))})
	if e == nil || got != "" {
		t.Fatal("must recover stale handler before accepting any token")
	}
}
func TestCallbackRefusesNonLoopback(t *testing.T) {
	for _, s := range []string{"https://127.0.0.1:80/callback", "http://localhost:80/callback", "http://127.0.0.1.example.com:80/callback", "http://127.0.0.1:80/other", "http://127.0.0.1:80/callback?x=1"} {
		if _, e := parseLoopback(s); e == nil {
			t.Fatal("accepted untrusted endpoint")
		}
	}
}
