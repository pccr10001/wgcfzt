package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pccr10001/wgcfzt/internal/api"
	"github.com/pccr10001/wgcfzt/internal/app"
)

func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := New()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	e := cmd.Execute()
	return out.String(), e
}
func TestCLIImportStatusGenerateAndCredentialRedaction(t *testing.T) {
	dir := t.TempDir()
	private, _ := app.WGKey()
	public, _ := app.WGPublic(private)
	r := api.Registration{ID: "test-device", Token: "test-bearer", Key: public, TunnelType: "wireguard"}
	r.Account.ID = "test-account"
	r.Config.Interface.Addresses.V4 = "100.96.0.2"
	var peer api.Peer
	peer.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	peer.Endpoint.V4 = "162.159.193.4:0"
	r.Config.Peers = []api.Peer{peer}
	b, _ := json.Marshal(r)
	registration := filepath.Join(dir, "registration.json")
	os.WriteFile(registration, b, 0600)
	key := filepath.Join(dir, "key")
	os.WriteFile(key, []byte(private), 0600)
	root := filepath.Join(dir, "config")
	out, e := execute(t, "--config-dir", root, "--profile", "example", "import", "--team", "example", "--registration", registration, "--key-file", key)
	if e != nil {
		t.Fatal(out, e)
	}
	for _, args := range [][]string{{"status", "--offline"}, {"generate", "--offline"}, {"devices", "list", "--offline"}} {
		out, e = execute(t, append([]string{"--config-dir", root, "--profile", "example"}, args...)...)
		if e != nil {
			t.Fatal(out, e)
		}
		if strings.Contains(out, private) || strings.Contains(out, "test-bearer") {
			t.Fatal("CLI leaked credentials")
		}
	}
	if _, e = os.Stat(filepath.Join(root, "profiles", "example", "wg-profile.conf")); e != nil {
		t.Fatal("profile was not generated", e)
	}
	if _, e = execute(t, "--config-dir", root, "--profile", "example", "import", "--team", "example", "--registration", registration, "--key-file", key); e == nil {
		t.Fatal("existing profile overwritten")
	}
	if _, e = execute(t, "--config-dir", root, "--profile", "example", "reg", "--team", "example", "--accept-tos"); e == nil {
		t.Fatal("existing registration unexpectedly entered login")
	}
}
