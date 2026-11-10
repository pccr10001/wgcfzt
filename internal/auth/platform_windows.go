//go:build windows

package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/pccr10001/wgcfzt/internal/store"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const protocolKey = `Software\Classes\com.cloudflare.warp`

type regValue struct {
	Type uint32
	Data []byte
}
type regTree struct {
	Values   map[string]regValue
	Children map[string]*regTree
}
type backup struct {
	Original         *regTree
	InstalledCommand string
	Restoring        bool `json:"restoring,omitempty"`
}

func backupPath(dir string) string { return filepath.Join(dir, "protocol-backup.json") }

func snapshot(path string) (*regTree, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.READ)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer k.Close()
	t := &regTree{Values: map[string]regValue{}, Children: map[string]*regTree{}}
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		n, typ, e := k.GetValue(name, nil)
		if e != nil {
			return nil, e
		}
		data := make([]byte, n)
		_, _, e = k.GetValue(name, data)
		if e != nil {
			return nil, e
		}
		t.Values[name] = regValue{typ, data}
	}
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	for _, name := range subs {
		t.Children[name], err = snapshot(path + `\` + name)
		if err != nil {
			return nil, err
		}
	}
	return t, nil
}
func removeTree(path string) error {
	k, e := registry.OpenKey(registry.CURRENT_USER, path, registry.READ|registry.WRITE)
	if errors.Is(e, registry.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	names, e := k.ReadSubKeyNames(-1)
	k.Close()
	if e != nil {
		return e
	}
	for _, name := range names {
		if e = removeTree(path + `\` + name); e != nil {
			return e
		}
	}
	return registry.DeleteKey(registry.CURRENT_USER, path)
}

var regSetValue = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegSetValueExW")

func restoreTree(path string, t *regTree) error {
	if t == nil {
		return nil
	}
	k, _, e := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if e != nil {
		return e
	}
	defer k.Close()
	names, e := k.ReadValueNames(-1)
	if e != nil {
		return e
	}
	for _, name := range names {
		if _, ok := t.Values[name]; !ok {
			if e = k.DeleteValue(name); e != nil {
				return e
			}
		}
	}
	children, e := k.ReadSubKeyNames(-1)
	if e != nil {
		return e
	}
	for _, name := range children {
		if _, ok := t.Children[name]; !ok {
			if e = removeTree(path + `\` + name); e != nil {
				return e
			}
		}
	}
	for name, v := range t.Values {
		n, e := windows.UTF16PtrFromString(name)
		if e != nil {
			return e
		}
		var data uintptr
		if len(v.Data) > 0 {
			data = uintptr(unsafe.Pointer(&v.Data[0]))
		}
		r, _, _ := regSetValue.Call(uintptr(k), uintptr(unsafe.Pointer(n)), 0, uintptr(v.Type), data, uintptr(len(v.Data)))
		runtime.KeepAlive(n)
		runtime.KeepAlive(v.Data)
		if r != 0 {
			return syscall.Errno(r)
		}
	}
	for name, child := range t.Children {
		if e = restoreTree(path+`\`+name, child); e != nil {
			return e
		}
	}
	return nil
}
func commandValue() (string, error) {
	k, e := registry.OpenKey(registry.CURRENT_USER, protocolKey+`\shell\open\command`, registry.READ)
	if e != nil {
		return "", e
	}
	defer k.Close()
	v, _, e := k.GetStringValue("")
	return v, e
}

func protocolMutex() (func(), error) {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, e
	}
	n, e := windows.UTF16PtrFromString(`Global\wgcfzt-protocol-` + u.User.Sid.String())
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateMutex(nil, false, n)
	if e != nil && !errors.Is(e, windows.ERROR_ALREADY_EXISTS) {
		return nil, e
	}
	r, e := windows.WaitForSingleObject(h, 0)
	if e != nil || (r != windows.WAIT_OBJECT_0 && r != windows.WAIT_ABANDONED) {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("another login owns the protocol handler")
	}
	return func() { windows.ReleaseMutex(h); windows.CloseHandle(h) }, nil
}

func takeover(dir, exe string) (func() error, error) {
	unlock, err := protocolMutex()
	if err != nil {
		return nil, err
	}
	fail := func(e error) (func() error, error) { unlock(); return nil, e }
	if _, err = os.Stat(backupPath(dir)); err == nil {
		return fail(fmt.Errorf("a protocol backup exists; run wgcfzt recover first"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	// Windows protects UserChoice with a hash. Never edit or forge it.
	k, e := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\Shell\Associations\UrlAssociations\com.cloudflare.warp\UserChoice`, registry.READ)
	if e == nil {
		k.Close()
		return fail(fmt.Errorf("Windows UserChoice association is protected; use manual login"))
	}
	if !errors.Is(e, registry.ErrNotExist) {
		return fail(e)
	}
	original, e := snapshot(protocolKey)
	if e != nil {
		return fail(e)
	}
	if original != nil {
		if v, ok := original.Values[""]; ok && strings.Contains(strings.ReplaceAll(string(v.Data), "\x00", ""), "wgcfzt temporary login") {
			return fail(ErrRecoveryRequired)
		}
	}
	command := `"` + exe + `" --config-dir "` + dir + `" callback -- "%1"`
	b := backup{Original: original, InstalledCommand: command}
	if e = store.WriteJSON(backupPath(dir), b); e != nil {
		return fail(e)
	}
	rollback := func() error {
		b.Restoring = true
		if e := store.WriteJSON(backupPath(dir), b); e != nil {
			return e
		}
		if e := putOriginal(original); e != nil {
			return e
		}
		return os.Remove(backupPath(dir))
	}
	install := func() error {
		k, _, e := registry.CreateKey(registry.CURRENT_USER, protocolKey+`\shell\open\command`, registry.ALL_ACCESS)
		if e != nil {
			return e
		}
		e = k.SetStringValue("", command)
		k.Close()
		if e != nil {
			return e
		}
		k, _, e = registry.CreateKey(registry.CURRENT_USER, protocolKey, registry.ALL_ACCESS)
		if e != nil {
			return e
		}
		defer k.Close()
		if e = k.SetStringValue("", "wgcfzt temporary login"); e != nil {
			return e
		}
		return k.SetStringValue("URL Protocol", "")
	}
	if e = install(); e != nil {
		r := rollback()
		return fail(errors.Join(e, r))
	}
	notifyAssociationChange()
	if active, e := effectiveCommand(); e != nil || !strings.EqualFold(active, command) {
		r := rollback()
		return fail(errors.Join(fmt.Errorf("OS did not select the temporary handler"), r))
	}
	return func() error { defer unlock(); return recoverOwned(dir) }, nil
}

func recoverOwned(dir string) error {
	b, e := os.ReadFile(backupPath(dir))
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	var saved backup
	if json.Unmarshal(b, &saved) != nil || saved.InstalledCommand == "" {
		return fmt.Errorf("invalid protocol backup")
	}
	actual, e := snapshot(protocolKey)
	if e != nil {
		return e
	}
	if reflect.DeepEqual(actual, saved.Original) {
		return os.Remove(backupPath(dir))
	}
	current, e := commandValue()
	if e != nil && !(saved.Restoring && errors.Is(e, registry.ErrNotExist)) {
		return fmt.Errorf("cannot establish ownership of temporary handler: %w", e)
	}
	if e == nil && current != saved.InstalledCommand {
		return fmt.Errorf("protocol association changed externally; refusing to overwrite it")
	}
	saved.Restoring = true
	if e = store.WriteJSON(backupPath(dir), saved); e != nil {
		return e
	}
	if e = putOriginal(saved.Original); e != nil {
		return e
	}
	return os.Remove(backupPath(dir))
}

func putOriginal(original *regTree) error {
	var e error
	if original == nil {
		e = removeTree(protocolKey)
	} else {
		e = restoreTree(protocolKey, original)
	}
	notifyAssociationChange()
	return e
}

var associationChanged = windows.NewLazySystemDLL("shell32.dll").NewProc("SHChangeNotify")

func notifyAssociationChange() { associationChanged.Call(0x08000000, 0, 0, 0) }
func Recover(dir string) error {
	unlock, e := protocolMutex()
	if e != nil {
		return e
	}
	defer unlock()
	return recoverOwned(dir)
}

var assocQuery = windows.NewLazySystemDLL("shlwapi.dll").NewProc("AssocQueryStringW")

func effectiveCommand() (string, error) {
	n, _ := windows.UTF16PtrFromString("com.cloudflare.warp")
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	r, _, _ := assocQuery.Call(0, 1, uintptr(unsafe.Pointer(n)), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return "", fmt.Errorf("cannot query effective URL protocol handler")
	}
	return windows.UTF16ToString(buf), nil
}
func openBrowser(browser, url string) error {
	if browser == "firefox" {
		p, e := exec.LookPath("firefox.exe")
		if e != nil {
			for _, env := range []string{"PROGRAMFILES", "PROGRAMFILES(X86)"} {
				candidate := filepath.Join(os.Getenv(env), "Mozilla Firefox", "firefox.exe")
				if _, e = os.Stat(candidate); e == nil {
					p = candidate
					break
				}
			}
		}
		if p == "" {
			return fmt.Errorf("Firefox is not installed")
		}
		return exec.Command(p, "-new-tab", url).Start()
	}
	if browser != "default" && browser != "" {
		return fmt.Errorf("browser must be firefox or default")
	}
	u, e := windows.UTF16PtrFromString(url)
	if e != nil {
		return e
	}
	return windows.ShellExecute(0, nil, u, nil, nil, windows.SW_SHOWNORMAL)
}

func checkBrowser(browser string) error {
	if browser != "firefox" {
		return nil
	}
	files, e := filepath.Glob(filepath.Join(os.Getenv("APPDATA"), "Mozilla", "Firefox", "Profiles", "*", "handlers.json"))
	if e != nil {
		return e
	}
	for _, file := range files {
		b, e := os.ReadFile(file)
		if e != nil {
			return fmt.Errorf("cannot check Firefox protocol preferences; use manual login")
		}
		var h struct {
			Schemes map[string]struct {
				Action int `json:"action"`
			} `json:"schemes"`
		}
		if json.Unmarshal(b, &h) != nil {
			return fmt.Errorf("cannot parse Firefox protocol preferences; use manual login")
		}
		if choice, ok := h.Schemes["com.cloudflare.warp"]; ok && choice.Action != 4 {
			return fmt.Errorf("Firefox has a custom protocol preference; use manual login to avoid opening another application")
		}
	}
	return nil
}
