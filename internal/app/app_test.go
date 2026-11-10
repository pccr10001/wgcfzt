package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	"github.com/pccr10001/wgcfzt/internal/api"
	"github.com/pccr10001/wgcfzt/internal/store"
)

func TestRegistrationVNetExportsAndDeregistration(t *testing.T) {
	for _, protocol := range []string{"wireguard", "masque"} {
		t.Run(protocol, func(t *testing.T) {
			var reg api.Registration
			selected := "default-id"
			deleted := false
			serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			der, _ := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
			peerPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == "POST" && r.URL.Path == "/v0a4471/reg" {
					if r.Header.Get("CF-Access-Jwt-Assertion") != "team-jwt" {
						t.Error("missing registration JWT")
					}
					var in map[string]string
					json.NewDecoder(r.Body).Decode(&in)
					reg.ID = "device-id"
					reg.Token = "device-token"
					reg.Account.ID = "account-id"
					reg.Key = in["key"]
					reg.TunnelType = "wireguard"
					reg.Config.Interface.Addresses.V4 = "100.96.0.2"
					reg.Config.Interface.Addresses.V6 = "2606:4700:cf1::2"
					var peer api.Peer
					peer.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
					peer.Endpoint.V4 = "162.159.193.4:0"
					peer.Endpoint.V6 = "[2606:4700::1]:0"
					peer.Endpoint.Ports = []int{2408}
					reg.Config.Peers = []api.Peer{peer}
					json.NewEncoder(w).Encode(reg)
					return
				}
				if r.Header.Get("Authorization") != "Bearer device-token" {
					t.Error("missing device authorization")
				}
				switch {
				case r.Method == "PATCH" && r.URL.Path == "/v0a4471/reg/device-id":
					var in map[string]string
					json.NewDecoder(r.Body).Decode(&in)
					if in["tunnel_type"] == "masque" {
						reg.Key = in["key"]
						reg.TunnelType = "masque"
						reg.Config.Peers[0].PublicKey = peerPEM
					}
					reg.Token = ""
					json.NewEncoder(w).Encode(reg)
				case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/virtualnetworks"):
					fmt.Fprintf(w, `{"success":true,"result":{"selected_virtual_network_id":%q,"virtual_networks":[{"id":"default-id","name":"default"},{"id":"labs-id","name":"labs"}]}}`, selected)
				case r.Method == "PATCH" && strings.HasSuffix(r.URL.Path, "/virtualnetworks/labs-id"):
					selected = "labs-id"
					fmt.Fprint(w, `{"success":true}`)
				case r.Method == "DELETE" && r.URL.Path == "/v0a4471/reg/device-id":
					deleted = true
					w.WriteHeader(204)
				default:
					t.Error("unexpected request", r.Method, r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer s.Close()
			client := api.New()
			client.BaseURL = s.URL
			a := App{API: client, Store: store.Store{Dir: t.TempDir()}}
			p, e := a.Register(context.Background(), RegisterOptions{Name: "labs", Team: "example", Protocol: protocol, JWT: "team-jwt", VNet: "labs"})
			if e != nil {
				t.Fatal(e)
			}
			if p.SelectedVNet != "labs-id" || p.AccessToken != "device-token" {
				t.Fatal("state was not retained")
			}
			path, e := a.Export(p, ExportOptions{MTU: 1280, Keepalive: 25})
			if e != nil {
				t.Fatal(e)
			}
			data, _ := os.ReadFile(path)
			if protocol == "wireguard" {
				if !strings.Contains(string(data), "Endpoint = 162.159.193.4:2408") || !strings.Contains(string(data), "Address = 100.96.0.2/32") {
					t.Fatal("invalid WireGuard export")
				}
				if _, e = a.Export(p, ExportOptions{Format: "usque"}); e == nil {
					t.Fatal("WireGuard key exported as MASQUE")
				}
			} else {
				var cfg map[string]string
				if e = json.Unmarshal(data, &cfg); e != nil {
					t.Fatal(e)
				}
				key, e := base64.StdEncoding.DecodeString(cfg["private_key"])
				if e != nil {
					t.Fatal(e)
				}
				if _, e = x509.ParseECPrivateKey(key); e != nil {
					t.Fatal("usque cannot parse SEC1 key", e)
				}
				if cfg["endpoint_v6"] != "2606:4700::1" || cfg["access_token"] != "device-token" || cfg["id"] != "device-id" {
					t.Fatal("invalid usque export")
				}
			}
			if e = a.Deregister(context.Background(), "labs"); e != nil {
				t.Fatal(e)
			}
			if !deleted {
				t.Fatal("remote deletion missing")
			}
			got, e := a.Store.Load("labs")
			if e != nil {
				t.Fatal(e)
			}
			if got.State != "deregistered" || got.AccessToken != "" || got.WGPrivateKey != "" || got.MasquePrivateKey != "" {
				t.Fatal("credentials retained after deletion")
			}
			if _, e = os.Stat(path); !os.IsNotExist(e) {
				t.Fatal("exported credentials retained")
			}
		})
	}
}
func TestVNetReadbackFailureDoesNotClaimSuccess(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PATCH" {
			fmt.Fprint(w, `{"success":true}`)
		} else {
			fmt.Fprint(w, `{"success":true,"result":{"selected_virtual_network_id":"old","virtual_networks":[{"id":"new","name":"labs"}]}}`)
		}
	}))
	defer s.Close()
	c := api.New()
	c.BaseURL = s.URL
	a := App{API: c, Store: store.Store{Dir: t.TempDir()}}
	p := &store.Profile{Name: "test", State: "ready", DeviceID: "id", AccountID: "account", AccessToken: "token", SelectedVNet: "old"}
	if e := a.Store.Save(p); e != nil {
		t.Fatal(e)
	}
	if _, e := a.SelectVNet(context.Background(), "test", "labs"); e == nil {
		t.Fatal("accepted wrong VNET readback")
	}
	got, _ := a.Store.Load("test")
	if got.SelectedVNet != "old" {
		t.Fatal("wrong selected VNET persisted")
	}
}
func TestExportRejectsMismatchedKeyAndInvalidOptions(t *testing.T) {
	private, _ := WGKey()
	pub, _ := WGPublic(private)
	a := App{Store: store.Store{Dir: t.TempDir()}}
	p := &store.Profile{Name: "test", State: "ready", Protocol: "wireguard", WGPrivateKey: private}
	p.Registration.Key = pub
	p.Registration.TunnelType = "wireguard"
	for _, o := range []ExportOptions{{MTU: 1280, Keepalive: 65536}, {MTU: 1}, {Format: "usque"}} {
		if _, e := a.Export(p, o); e == nil {
			t.Fatal("invalid export accepted")
		}
	}
	if _, e := os.Stat(filepath.Join(a.Store.Dir, "profiles", "test", "usque.json")); !os.IsNotExist(e) {
		t.Fatal("invalid export wrote credentials")
	}
}
