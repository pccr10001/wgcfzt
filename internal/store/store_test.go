package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfileTraversalAndAtomicReplacement(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	for _, name := range []string{"", "../escape", "..", "/root", `a\b`, "a/b", "trailing."} {
		if _, e := s.ProfileDir(name); e == nil {
			t.Fatal("accepted unsafe profile", name)
		}
	}
	p := &Profile{Name: "valid-profile", State: "pending", WGPrivateKey: "test-secret"}
	if e := s.Save(p); e != nil {
		t.Fatal(e)
	}
	p.State = "ready"
	if e := s.Save(p); e != nil {
		t.Fatal(e)
	}
	got, e := s.Load(p.Name)
	if e != nil || got.State != "ready" || got.WGPrivateKey != "test-secret" {
		t.Fatal("profile roundtrip", e)
	}
	files, e := filepath.Glob(filepath.Join(s.Dir, "profiles", p.Name, ".wgcfzt-*"))
	if e != nil || len(files) != 0 {
		t.Fatal("temporary credential files retained")
	}
}
func TestLockExcludesAnotherWriter(t *testing.T) {
	d := t.TempDir()
	unlock, e := Lock(d)
	if e != nil {
		t.Fatal(e)
	}
	if another, e := Lock(d); e == nil {
		another()
		t.Fatal("concurrent lock accepted")
	}
	unlock()
	again, e := Lock(d)
	if e != nil {
		t.Fatal("lock not released", e)
	}
	again()
}
func TestExportDoesNotChangeParentPermissions(t *testing.T) {
	d := t.TempDir()
	before, e := os.Stat(d)
	if e != nil {
		t.Fatal(e)
	}
	if e = WriteFile(filepath.Join(d, "profile.conf"), []byte("private data")); e != nil {
		t.Fatal(e)
	}
	after, _ := os.Stat(d)
	if before.Mode() != after.Mode() {
		t.Fatal("existing export directory permissions changed")
	}
}
