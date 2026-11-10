package app

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pccr10001/wgcfzt/internal/api"
	"github.com/pccr10001/wgcfzt/internal/store"
)

type App struct {
	API   *api.Client
	Store store.Store
}
type RegisterOptions struct {
	Name, Team, Protocol, DeviceName, JWT, VNet string
	Resume                                      bool
}

func WGKey() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	b[0] &= 248
	b[31] = (b[31] & 127) | 64
	return base64.StdEncoding.EncodeToString(b), nil
}
func WGPublic(private string) (string, error) {
	b, e := base64.StdEncoding.DecodeString(private)
	if e != nil {
		return "", fmt.Errorf("invalid WireGuard private key")
	}
	k, e := ecdh.X25519().NewPrivateKey(b)
	if e != nil {
		return "", fmt.Errorf("invalid WireGuard private key")
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}
func MasqueKey() (string, error) {
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return "", e
	}
	b, e := x509.MarshalECPrivateKey(k)
	return base64.StdEncoding.EncodeToString(b), e
}
func MasquePublic(private string) (string, error) {
	b, e := base64.StdEncoding.DecodeString(private)
	if e != nil {
		return "", fmt.Errorf("invalid MASQUE private key")
	}
	k, e := x509.ParseECPrivateKey(b)
	if e != nil || k.Curve != elliptic.P256() {
		return "", fmt.Errorf("invalid P-256 private key")
	}
	b, e = x509.MarshalPKIXPublicKey(&k.PublicKey)
	return base64.StdEncoding.EncodeToString(b), e
}

func (a *App) Register(ctx context.Context, o RegisterOptions) (*store.Profile, error) {
	d, e := a.Store.ProfileDir(o.Name)
	if e != nil {
		return nil, e
	}
	unlock, e := store.Lock(d)
	if e != nil {
		return nil, e
	}
	defer unlock()
	p, e := a.Store.Load(o.Name)
	if e == nil && !o.Resume {
		return nil, fmt.Errorf("profile already exists; use another --profile or --resume for an interrupted operation")
	}
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if o.Resume && p == nil {
		return nil, fmt.Errorf("no profile to resume")
	}
	if p == nil {
		if o.Protocol != "wireguard" && o.Protocol != "masque" {
			return nil, fmt.Errorf("protocol must be wireguard or masque")
		}
		wg, e := WGKey()
		if e != nil {
			return nil, e
		}
		p = &store.Profile{Name: o.Name, Team: o.Team, Protocol: o.Protocol, State: "pending", WGPrivateKey: wg}
		if o.Protocol == "masque" {
			p.MasquePrivateKey, e = MasqueKey()
			if e != nil {
				return nil, e
			}
		}
		if e = a.Store.Save(p); e != nil {
			return nil, e
		}
	} else if p.Team != o.Team || p.Protocol != o.Protocol {
		return nil, fmt.Errorf("resume must use the original team and protocol")
	}
	if p.State == "deregistered" {
		return nil, fmt.Errorf("profile is deregistered; use a new profile name")
	}
	if p.DeviceID == "" {
		if o.JWT == "" {
			return nil, fmt.Errorf("a current team JWT is required to register")
		}
		pub, e := WGPublic(p.WGPrivateKey)
		if e != nil {
			return nil, e
		}
		serial := make([]byte, 8)
		if _, e = rand.Read(serial); e != nil {
			return nil, e
		}
		payload := map[string]any{"key": pub, "key_type": "curve25519", "tunnel_type": "wireguard", "install_id": "", "fcm_token": "", "tos": time.Now().UTC().Format("2006-01-02T15:04:05.000-07:00"), "model": "PC", "serial_number": hex.EncodeToString(serial), "os_version": "", "locale": "en_US"}
		if o.DeviceName != "" {
			payload["name"] = o.DeviceName
		}
		var r api.Registration
		if e = a.API.Do(ctx, "POST", "/"+api.Version+"/reg", "", o.JWT, payload, &r); e != nil {
			return nil, fmt.Errorf("registration failed; pending key is retained; if the response was lost, inspect server-side devices before explicitly retrying --resume: %w", e)
		}
		// Save credentials before any further request or validation, so partial success is recoverable.
		p.DeviceID = r.ID
		p.AccountID = r.Account.ID
		p.AccessToken = r.Token
		p.Registration = r
		p.State = "registered"
		if e = a.Store.Save(p); e != nil {
			return nil, fmt.Errorf("registration succeeded but saving credentials failed: %w", e)
		}
		if r.ID == "" || r.Token == "" || r.Account.ID == "" {
			return nil, fmt.Errorf("registration response omitted credentials; retained response needs inspection")
		}
		if r.Key != pub || r.TunnelType != "wireguard" {
			return nil, fmt.Errorf("registration returned an unexpected key or tunnel type")
		}
	}
	if p.Protocol == "masque" && p.Registration.TunnelType != "masque" {
		pub, e := MasquePublic(p.MasquePrivateKey)
		if e != nil {
			return nil, e
		}
		payload := map[string]any{"key": pub, "key_type": "secp256r1", "tunnel_type": "masque"}
		if o.DeviceName != "" {
			payload["name"] = o.DeviceName
		}
		var r api.Registration
		if e = a.API.Do(ctx, "PATCH", api.RegPath(p.DeviceID), p.AccessToken, "", payload, &r); e != nil {
			return nil, fmt.Errorf("MASQUE enrollment interrupted; credentials retained; retry reg --resume: %w", e)
		}
		if r.ID != p.DeviceID || r.Key != pub || r.TunnelType != "masque" {
			return nil, fmt.Errorf("MASQUE enrollment returned an unexpected registration")
		}
		p.Registration = r
		if e = a.Store.Save(p); e != nil {
			return nil, e
		}
	}
	p.State = "ready"
	if e = a.Store.Save(p); e != nil {
		return nil, e
	}
	if o.VNet != "" {
		if _, e = a.selectVNet(ctx, p, o.VNet); e != nil {
			return nil, fmt.Errorf("registration saved; VNET selection failed: %w", e)
		}
	} else {
		n, e := a.API.Networks(ctx, p.AccountID, p.DeviceID, p.AccessToken)
		if e != nil {
			return nil, fmt.Errorf("registration saved; listing VNETs failed: %w", e)
		}
		p.SelectedVNet = n.Selected
		for _, v := range n.Networks {
			if v.ID == n.Selected {
				p.SelectedVNetName = v.Name
			}
		}
		if e = a.Store.Save(p); e != nil {
			return nil, e
		}
	}
	return p, nil
}

func (a *App) LoadReady(name string) (*store.Profile, error) {
	p, e := a.Store.Load(name)
	if e != nil {
		return nil, e
	}
	if p.State != "ready" || p.DeviceID == "" || p.AccessToken == "" {
		return nil, fmt.Errorf("profile is %s; finish registration or choose a ready profile", p.State)
	}
	return p, nil
}
func (a *App) Refresh(ctx context.Context, p *store.Profile) error {
	r, e := a.API.Get(ctx, p.DeviceID, p.AccessToken)
	if e != nil {
		return e
	}
	if r.ID != p.DeviceID {
		return fmt.Errorf("server returned a different registration")
	}
	var pub string
	if p.Protocol == "wireguard" {
		pub, e = WGPublic(p.WGPrivateKey)
	} else {
		pub, e = MasquePublic(p.MasquePrivateKey)
	}
	if e != nil {
		return e
	}
	if r.Key != pub || r.TunnelType != p.Protocol {
		return fmt.Errorf("remote tunnel key or protocol changed; refusing to export a mismatched configuration")
	}
	p.Registration = r
	return a.Store.Save(p)
}
func (a *App) selectVNet(ctx context.Context, p *store.Profile, selector string) (api.Network, error) {
	n, e := a.API.Networks(ctx, p.AccountID, p.DeviceID, p.AccessToken)
	if e != nil {
		return api.Network{}, e
	}
	var matches []api.Network
	for _, v := range n.Networks {
		if v.ID == selector || v.Name == selector {
			matches = append(matches, v)
		}
	}
	if len(matches) != 1 {
		return api.Network{}, fmt.Errorf("VNET name or UUID must identify exactly one available network")
	}
	v := matches[0]
	if e = a.API.Select(ctx, p.AccountID, p.DeviceID, p.AccessToken, v.ID); e != nil {
		return v, e
	}
	n, e = a.API.Networks(ctx, p.AccountID, p.DeviceID, p.AccessToken)
	if e != nil {
		return v, e
	}
	if n.Selected != v.ID {
		return v, fmt.Errorf("VNET readback did not match selection")
	}
	p.SelectedVNet = v.ID
	p.SelectedVNetName = v.Name
	return v, a.Store.Save(p)
}
func (a *App) SelectVNet(ctx context.Context, name, selector string) (api.Network, error) {
	d, e := a.Store.ProfileDir(name)
	if e != nil {
		return api.Network{}, e
	}
	unlock, e := store.Lock(d)
	if e != nil {
		return api.Network{}, e
	}
	defer unlock()
	p, e := a.LoadReady(name)
	if e != nil {
		return api.Network{}, e
	}
	return a.selectVNet(ctx, p, selector)
}
func (a *App) Deregister(ctx context.Context, name string) error {
	d, e := a.Store.ProfileDir(name)
	if e != nil {
		return e
	}
	unlock, e := store.Lock(d)
	if e != nil {
		return e
	}
	defer unlock()
	p, e := a.Store.Load(name)
	if e != nil {
		return e
	}
	if p.State == "deregistered" {
		return fmt.Errorf("profile is already deregistered")
	}
	if p.DeviceID == "" || p.AccessToken == "" {
		return fmt.Errorf("no saved remote registration to delete")
	}
	if e = a.API.Do(ctx, "DELETE", api.RegPath(p.DeviceID), p.AccessToken, "", nil, nil); e != nil {
		return e
	}
	p.State = "deregistered"
	p.AccessToken = ""
	p.WGPrivateKey = ""
	p.MasquePrivateKey = ""
	p.Registration = api.Registration{}
	if e = a.Store.Save(p); e != nil {
		return fmt.Errorf("remote registration deleted, but local cleanup failed: %w", e)
	}
	for _, name := range []string{"wg-profile.conf", "usque.json"} {
		if e = os.Remove(filepath.Join(d, name)); e != nil && !os.IsNotExist(e) {
			return fmt.Errorf("registration deleted, but exported file cleanup failed: %w", e)
		}
	}
	return nil
}

type ExportOptions struct {
	Format, Output  string
	MTU, Keepalive  int
	DNS, AllowedIPs []string
}

func (a *App) Export(p *store.Profile, o ExportOptions) (string, error) {
	if p.State != "ready" {
		return "", fmt.Errorf("profile is not ready")
	}
	if o.Format == "" {
		o.Format = p.Protocol
		if o.Format == "masque" {
			o.Format = "usque"
		}
	}
	d, e := a.Store.ProfileDir(p.Name)
	if e != nil {
		return "", e
	}
	if o.Format == "usque" {
		if p.Protocol != "masque" {
			return "", fmt.Errorf("usque requires its own P-256 MASQUE registration; create a separate profile with reg --protocol masque")
		}
		if len(p.Registration.Config.Peers) == 0 {
			return "", fmt.Errorf("no registered peer")
		}
		pub, e := MasquePublic(p.MasquePrivateKey)
		if e != nil {
			return "", e
		}
		if pub != p.Registration.Key || p.Registration.TunnelType != "masque" {
			return "", fmt.Errorf("MASQUE key does not match registration")
		}
		peer := p.Registration.Config.Peers[0]
		if e = validateMasquePeer(peer.PublicKey); e != nil {
			return "", e
		}
		v4, e := endpointIP(peer.Endpoint.V4)
		if e != nil {
			return "", e
		}
		v6, e := endpointIP(peer.Endpoint.V6)
		if e != nil {
			return "", e
		}
		config := map[string]string{"private_key": p.MasquePrivateKey, "endpoint_v4": v4, "endpoint_v6": v6, "endpoint_h2_v4": "162.159.198.2", "endpoint_h2_v6": "", "endpoint_pub_key": peer.PublicKey, "id": p.DeviceID, "access_token": p.AccessToken, "ipv4": p.Registration.Config.Interface.Addresses.V4, "ipv6": p.Registration.Config.Interface.Addresses.V6}
		if o.Output == "" {
			o.Output = filepath.Join(d, "usque.json")
		}
		return o.Output, store.WriteJSON(o.Output, config)
	}
	if o.Format != "wireguard" {
		return "", fmt.Errorf("format must be wireguard or usque")
	}
	if p.Protocol != "wireguard" {
		return "", fmt.Errorf("WireGuard export requires a WireGuard profile")
	}
	if o.MTU < 576 || o.MTU > 9000 || o.Keepalive < 0 || o.Keepalive > 65535 {
		return "", fmt.Errorf("invalid MTU or keepalive interval")
	}
	pub, e := WGPublic(p.WGPrivateKey)
	if e != nil {
		return "", e
	}
	if pub != p.Registration.Key || p.Registration.TunnelType != "wireguard" {
		return "", fmt.Errorf("WireGuard key does not match registration")
	}
	if len(p.Registration.Config.Peers) == 0 {
		return "", fmt.Errorf("no registered peer")
	}
	peer := p.Registration.Config.Peers[0]
	b, e := base64.StdEncoding.DecodeString(peer.PublicKey)
	if e != nil || len(b) != 32 {
		return "", fmt.Errorf("invalid WireGuard peer public key")
	}
	endpoint, e := wireguardEndpoint(peer)
	if e != nil {
		return "", e
	}
	addresses := p.Registration.Config.Interface.Addresses
	var ips []string
	for _, s := range []string{addresses.V4, addresses.V6} {
		if s == "" {
			continue
		}
		ip, e := netip.ParseAddr(s)
		if e != nil {
			return "", fmt.Errorf("invalid interface address")
		}
		ips = append(ips, netip.PrefixFrom(ip, ip.BitLen()).String())
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no interface addresses")
	}
	if len(o.AllowedIPs) == 0 {
		o.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	}
	for _, s := range o.AllowedIPs {
		if _, e := netip.ParsePrefix(s); e != nil {
			return "", fmt.Errorf("invalid AllowedIPs CIDR")
		}
	}
	for _, s := range o.DNS {
		if _, e := netip.ParseAddr(s); e != nil {
			return "", fmt.Errorf("DNS must contain IP addresses")
		}
	}
	var result strings.Builder
	fmt.Fprintf(&result, "# VNET at export: %s\n# VNET selection is server-side registration state. Reconnect after switching.\n[Interface]\nPrivateKey = %s\nAddress = %s\nMTU = %d\n", p.SelectedVNet, p.WGPrivateKey, strings.Join(ips, ", "), o.MTU)
	if len(o.DNS) > 0 {
		fmt.Fprintf(&result, "DNS = %s\n", strings.Join(o.DNS, ", "))
	}
	fmt.Fprintf(&result, "\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\nEndpoint = %s\n", peer.PublicKey, strings.Join(o.AllowedIPs, ", "), endpoint)
	if o.Keepalive > 0 {
		fmt.Fprintf(&result, "PersistentKeepalive = %d\n", o.Keepalive)
	}
	if o.Output == "" {
		o.Output = filepath.Join(d, "wg-profile.conf")
	}
	return o.Output, store.WriteFile(o.Output, []byte(result.String()))
}

func endpointIP(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	host, _, e := net.SplitHostPort(s)
	if e != nil {
		host = s
	}
	ip, e := netip.ParseAddr(host)
	if e != nil {
		return "", fmt.Errorf("invalid tunnel endpoint IP")
	}
	return ip.String(), nil
}
func wireguardEndpoint(p api.Peer) (string, error) {
	for _, candidate := range []string{p.Endpoint.V4, p.Endpoint.V6} {
		if candidate == "" {
			continue
		}
		ap, e := netip.ParseAddrPort(candidate)
		if e != nil {
			continue
		}
		port := ap.Port()
		if port == 0 {
			port = 2408
			for _, n := range p.Endpoint.Ports {
				if n > 0 && n <= 65535 {
					port = uint16(n)
					break
				}
			}
		}
		return netip.AddrPortFrom(ap.Addr(), port).String(), nil
	}
	return "", fmt.Errorf("no valid peer IP endpoint")
}
