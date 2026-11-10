package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"github.com/pccr10001/wgcfzt/internal/api"
)

type Profile struct {
	Version          int              `json:"version"`
	Name             string           `json:"profile"`
	Team             string           `json:"team"`
	Protocol         string           `json:"protocol"`
	State            string           `json:"state"`
	DeviceID         string           `json:"device_id,omitempty"`
	AccountID        string           `json:"account_id,omitempty"`
	AccessToken      string           `json:"access_token,omitempty"`
	WGPrivateKey     string           `json:"wireguard_private_key,omitempty"`
	MasquePrivateKey string           `json:"masque_private_key,omitempty"`
	SelectedVNet     string           `json:"selected_vnet,omitempty"`
	SelectedVNetName string           `json:"selected_vnet_name,omitempty"`
	Updated          time.Time        `json:"updated_at"`
	Registration     api.Registration `json:"registration"`
}
type Store struct{ Dir string }

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func ValidateName(name string) error {
	if !validName.MatchString(name) || name == "." || name == ".." || name[len(name)-1:] == "." {
		return fmt.Errorf("profile must be 1-64 letters, digits, dots, dashes or underscores, starting with a letter or digit")
	}
	return nil
}
func DefaultDir() (string, error) {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "wgcfzt"), nil
		}
		return "", fmt.Errorf("LOCALAPPDATA is unset; specify --config-dir")
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		if !filepath.IsAbs(d) {
			return "", fmt.Errorf("XDG_CONFIG_HOME must be absolute")
		}
		return filepath.Join(d, "wgcfzt"), nil
	}
	h, err := os.UserHomeDir()
	return filepath.Join(h, ".config", "wgcfzt"), err
}
func SecureDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return securePath(path, true)
}
func (s Store) ProfileDir(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	return filepath.Join(s.Dir, "profiles", name), nil
}
func (s Store) Load(name string) (*Profile, error) {
	d, err := s.ProfileDir(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(d, "account.json"))
	if err != nil {
		return nil, fmt.Errorf("load profile %q: %w", name, err)
	}
	var p Profile
	if err = json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("invalid profile JSON")
	}
	if p.Name != name || p.Version != 1 {
		return nil, fmt.Errorf("unsupported or mismatched profile")
	}
	return &p, nil
}
func (s Store) Save(p *Profile) error {
	d, err := s.ProfileDir(p.Name)
	if err != nil {
		return err
	}
	p.Version = 1
	p.Updated = time.Now().UTC()
	// Keep the bearer credential in one field, not duplicated in the cached API response.
	p.Registration.Token = ""
	return WriteJSON(filepath.Join(d, "account.json"), p)
}
func WriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFile(path, append(b, '\n'))
}
func WriteFile(path string, b []byte) error {
	// Do not chmod/rewrite the ACL of a caller's existing export directory.
	d := filepath.Dir(path)
	if err := os.MkdirAll(d, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(d, ".wgcfzt-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = securePath(tmp, false); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, path)
}
func Lock(dir string) (func(), error) {
	if err := SecureDir(dir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("another wgcfzt operation is using this directory: %w", err)
	}
	return func() { f.Close() }, nil
}
