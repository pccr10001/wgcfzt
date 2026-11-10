package cli

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pccr10001/wgcfzt/internal/api"
	"github.com/pccr10001/wgcfzt/internal/app"
	"github.com/pccr10001/wgcfzt/internal/store"
)

func runInteractive(t *testing.T, a *app.App, input string, args ...string) (string, error) {
	t.Helper()
	c := newCommand(a)
	var out bytes.Buffer
	c.SetIn(strings.NewReader(input))
	c.SetOut(&out)
	c.SetErr(&out)
	c.SetArgs(append([]string{"--config-dir", a.Store.Dir}, args...))
	e := c.Execute()
	return out.String(), e
}

func TestInteractiveDevicesVNetAndDereg(t *testing.T) {
	selected := map[string]string{"a": "default-id", "b": "default-id"}
	deleted := ""
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := "a"
		if strings.Contains(r.URL.Path, "/b/") || strings.HasSuffix(r.URL.Path, "/b") {
			id = "b"
		}
		if r.Header.Get("Authorization") != "Bearer token-"+id {
			t.Error("wrong device token")
		}
		switch {
		case r.Method == "DELETE":
			deleted = id
			w.WriteHeader(204)
		case r.Method == "PATCH":
			selected[id] = "labs-id"
			fmt.Fprint(w, `{"success":true}`)
		default:
			fmt.Fprintf(w, `{"success":true,"result":{"selected_virtual_network_id":%q,"virtual_networks":[{"id":"default-id","name":"default"},{"id":"labs-id","name":"labs"}]}}`, selected[id])
		}
	}))
	defer s.Close()
	a := &app.App{API: api.New(), Store: store.Store{Dir: t.TempDir()}}
	a.API.BaseURL = s.URL
	for _, name := range []string{"a", "b"} {
		key, _ := app.WGKey()
		if e := a.Store.Save(&store.Profile{Name: name, State: "ready", Protocol: "wireguard", Team: "example", DeviceID: name, AccountID: "account", AccessToken: "token-" + name, WGPrivateKey: key}); e != nil {
			t.Fatal(e)
		}
	}
	out, e := runInteractive(t, a, "2\n2\n", "vnet")
	if e != nil || selected["a"] != "default-id" || selected["b"] != "labs-id" {
		t.Fatal(out, e, selected)
	}
	out, e = runInteractive(t, a, "", "vnet", "--device", "a", "--vnet", "labs", "--non-interactive")
	if e != nil || strings.Contains(out, "Choose a number") || selected["a"] != "labs-id" {
		t.Fatal(out, e)
	}
	out, e = runInteractive(t, a, "", "devices")
	if e != nil || !strings.Contains(out, "labs") || strings.Contains(out, "token-") {
		t.Fatal(out, e)
	}
	out, e = runInteractive(t, a, "q\n", "device", "dereg")
	if e == nil || deleted != "" {
		t.Fatal("cancelled deletion was not respected", out, e)
	}
	out, e = runInteractive(t, a, "2\nb\n", "device", "dereg")
	if e != nil || deleted != "b" {
		t.Fatal(out, e, deleted)
	}
	p, _ := a.Store.Load("b")
	if p.AccessToken != "" || p.WGPrivateKey != "" {
		t.Fatal("credentials retained")
	}
	out, e = runInteractive(t, a, "", "device", "dereg", "--device", "a", "--non-interactive")
	if e == nil || deleted != "b" {
		t.Fatal(out, e)
	}
	out, e = runInteractive(t, a, "", "device", "dereg", "--device", "a", "--yes", "--non-interactive")
	if e != nil || deleted != "a" {
		t.Fatal(out, e)
	}
}

func TestBareRegistrationAndConfigCommands(t *testing.T) {
	var reg api.Registration
	selected := "default-id"
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			reg.ID = "t.test-device"
			reg.Token = "test-token"
			reg.Account.ID = "account"
			reg.Key = body["key"]
			reg.TunnelType = "wireguard"
			reg.Config.Interface.Addresses.V4 = "100.96.0.2"
			var peer api.Peer
			peer.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
			peer.Endpoint.V4 = "162.159.193.4:2408"
			reg.Config.Peers = []api.Peer{peer}
			json.NewEncoder(w).Encode(reg)
		case r.Method == "PATCH":
			selected = "labs-id"
			fmt.Fprint(w, `{"success":true}`)
		case strings.Contains(r.URL.Path, "virtualnetworks"):
			fmt.Fprintf(w, `{"success":true,"result":{"selected_virtual_network_id":%q,"virtual_networks":[{"id":"default-id","name":"default"},{"id":"labs-id","name":"labs"}]}}`, selected)
		default:
			json.NewEncoder(w).Encode(reg)
		}
	}))
	defer s.Close()
	a := &app.App{API: api.New(), Store: store.Store{Dir: t.TempDir()}}
	a.API.BaseURL = s.URL
	claims := fmt.Sprintf(`{"iss":"https://example.cloudflareaccess.com","exp":%d}`, time.Now().Add(time.Hour).Unix())
	jwt := "header." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".signature"
	jwtFile := filepath.Join(t.TempDir(), "jwt")
	os.WriteFile(jwtFile, []byte(jwt), 0600)
	out, e := runInteractive(t, a, "example\nwork\n1\n\ny\n2\n", "reg", "--jwt-file", jwtFile)
	if e != nil || selected != "labs-id" {
		t.Fatal(out, e)
	}
	p, e := a.Store.Load("work")
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out, p.WGPrivateKey) || strings.Contains(out, jwt) || strings.Contains(out, "test-token") {
		t.Fatal("credential leak")
	}
	for _, args := range [][]string{{"config", "export", "--offline"}, {"generate", "--offline"}} {
		out, e = runInteractive(t, a, "", append(args, "--device", "t.test-device", "--non-interactive")...)
		if e != nil || strings.Contains(out, p.WGPrivateKey) {
			t.Fatal(out, e)
		}
	}
	out, e = runInteractive(t, a, "", "config", "showkey", "--device", "work")
	if e != nil || strings.TrimSpace(out) != p.WGPrivateKey {
		t.Fatal("explicit key display failed", e)
	}
	if _, e = runInteractive(t, a, "", "config", "usque", "--device", "work", "--offline"); e == nil {
		t.Fatal("WireGuard exported as MASQUE")
	}
	masqueKey, _ := app.MasqueKey()
	masquePub, _ := app.MasquePublic(masqueKey)
	pubDER, _ := base64.StdEncoding.DecodeString(masquePub)
	if _, e := x509.ParsePKIXPublicKey(pubDER); e != nil {
		t.Fatal(e)
	}
	p.Name = "masque"
	p.Protocol = "masque"
	p.DeviceID = "masque-device"
	p.MasquePrivateKey = masqueKey
	p.Registration.Key = masquePub
	p.Registration.TunnelType = "masque"
	p.Registration.Config.Peers[0].PublicKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	if e := a.Store.Save(p); e != nil {
		t.Fatal(e)
	}
	out, e = runInteractive(t, a, "", "config", "usque", "--device", "masque", "--offline")
	if e != nil || strings.Contains(out, masqueKey) {
		t.Fatal("MASQUE export failed", out, e)
	}
	b, e := os.ReadFile(filepath.Join(a.Store.Dir, "profiles", "masque", "usque.json"))
	if e != nil {
		t.Fatal(e)
	}
	var config map[string]string
	if json.Unmarshal(b, &config) != nil || config["private_key"] != masqueKey || config["id"] != "masque-device" {
		t.Fatal("invalid usque export")
	}
	out, e = runInteractive(t, a, "", "config", "showkey", "--device", "masque")
	if e != nil || strings.TrimSpace(out) != masqueKey {
		t.Fatal("wrong MASQUE private key", e)
	}
	if _, e = runInteractive(t, a, "", "config", "export", "--non-interactive", "--offline"); e == nil {
		t.Fatal("missing device prompted")
	}
	out, e = runInteractive(t, a, "", "--help")
	if e != nil {
		t.Fatal(e)
	}
	for _, group := range []string{"Registration:", "Devices and networks:", "Configuration:"} {
		if !strings.Contains(out, group) {
			t.Fatal("missing help group", group)
		}
	}
}

func TestPromptReaderPreservesFollowingInput(t *testing.T) {
	c := New()
	c.SetContext(context.Background())
	c.SetIn(strings.NewReader("first\nsecond\n"))
	c.SetOut(&bytes.Buffer{})
	first, e := newPrompts(c).line("first", "")
	if e != nil || first != "first" {
		t.Fatal(e)
	}
	second, e := newPrompts(c).line("second", "")
	if e != nil || second != "second" {
		t.Fatal("buffered input lost", e)
	}
}
