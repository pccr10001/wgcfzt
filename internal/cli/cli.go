package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pccr10001/wgcfzt/internal/api"
	"github.com/pccr10001/wgcfzt/internal/app"
	"github.com/pccr10001/wgcfzt/internal/auth"
	"github.com/pccr10001/wgcfzt/internal/store"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	defaultDir, _ := store.DefaultDir()
	var dir, profile string
	a := &app.App{API: api.New()}
	root := &cobra.Command{Use: "wgcfzt", Short: "Independent Zero Trust WARP registrations, VNET selection, WireGuard and usque exports", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().StringVar(&dir, "config-dir", defaultDir, "Configuration directory")
	root.PersistentFlags().StringVar(&profile, "profile", "default", "Named device registration")
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if dir == "" {
			return fmt.Errorf("specify --config-dir")
		}
		abs, e := filepath.Abs(dir)
		if e != nil {
			return e
		}
		dir = abs
		if e = store.ValidateName(profile); e != nil {
			return e
		}
		if e = store.SecureDir(dir); e != nil {
			return e
		}
		a.Store = store.Store{Dir: dir}
		return nil
	}
	var team, protocol, deviceName, jwtFile, vnet, browser string
	var manual, accepted, resume bool
	var timeout time.Duration
	reg := &cobra.Command{Use: "reg", Aliases: []string{"register", "login"}, Short: "Sign in, register a device, select a VNET, and generate its configuration", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if !accepted {
			return fmt.Errorf("review https://www.cloudflare.com/application/terms/ and pass --accept-tos to register")
		}
		if timeout <= 0 {
			return fmt.Errorf("--timeout must be positive")
		}
		if browser != "firefox" && browser != "default" {
			return fmt.Errorf("--browser must be firefox or default")
		}
		if protocol != "wireguard" && protocol != "masque" {
			return fmt.Errorf("--protocol must be wireguard or masque")
		}
		if _, e := os.Stat(filepath.Join(dir, "protocol-backup.json")); e == nil {
			return fmt.Errorf("a temporary protocol handler is still pending; finish that login or run wgcfzt recover before registration")
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		p, e := a.Store.Load(profile)
		if e == nil && !resume {
			return fmt.Errorf("profile exists; choose another --profile or --resume")
		}
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if resume && p == nil {
			return fmt.Errorf("no saved registration to resume")
		}
		if p != nil {
			if team == "" {
				team = p.Team
			}
			if !cmd.Flags().Changed("protocol") {
				protocol = p.Protocol
			}
		}
		if _, e = auth.TeamHost(team); e != nil {
			return e
		}
		var jwt string
		if p == nil || p.DeviceID == "" {
			if jwtFile != "" {
				var b []byte
				if jwtFile == "-" {
					b, e = io.ReadAll(io.LimitReader(cmd.InOrStdin(), 32769))
				} else {
					b, e = os.ReadFile(jwtFile)
				}
				if e != nil {
					return fmt.Errorf("read JWT file: %w", e)
				}
				if len(b) > 32768 {
					return fmt.Errorf("JWT input too large")
				}
				jwt, e = auth.ParseToken(string(b), team)
			} else {
				jwt, e = auth.Login(cmd.Context(), auth.Options{Team: team, Dir: dir, Browser: browser, Manual: manual, Timeout: timeout, In: cmd.InOrStdin(), Out: cmd.OutOrStdout()})
			}
			if e != nil {
				return e
			}
		}
		p, e = a.Register(cmd.Context(), app.RegisterOptions{Name: profile, Team: team, Protocol: protocol, DeviceName: deviceName, JWT: jwt, VNet: vnet, Resume: resume})
		if e != nil {
			return e
		}
		path, e := a.Export(p, app.ExportOptions{MTU: 1280, Keepalive: 25})
		if e != nil {
			return fmt.Errorf("registration saved, configuration export failed: %w", e)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Registered profile %s (%s), device %s\nVNET: %s\nConfiguration: %s\n", profile, p.Protocol, p.DeviceID, p.SelectedVNet, path)
		return nil
	}}
	reg.Flags().StringVar(&team, "team", "", "Zero Trust organization slug")
	reg.Flags().StringVar(&protocol, "protocol", "wireguard", "wireguard or masque (usque)")
	reg.Flags().StringVar(&deviceName, "name", "", "Device display name")
	reg.Flags().StringVar(&jwtFile, "jwt-file", "", "Read JWT/callback from file, or - for stdin; skips browser login")
	reg.Flags().StringVar(&vnet, "vnet", "", "Select VNET name or UUID after registration")
	reg.Flags().StringVar(&browser, "browser", "firefox", "firefox or default")
	reg.Flags().BoolVar(&manual, "manual", false, "Paste JWT/callback instead of taking over the URL protocol")
	reg.Flags().BoolVar(&accepted, "accept-tos", false, "Accept Cloudflare terms for registration")
	reg.Flags().BoolVar(&resume, "resume", false, "Explicitly resume a saved interrupted registration")
	reg.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "Login timeout")
	root.AddCommand(reg)

	callback := &cobra.Command{Use: "callback <URL>", Hidden: true, Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error { return auth.Deliver(cmd.Context(), dir, args[0]) }}
	root.AddCommand(callback)
	root.AddCommand(&cobra.Command{Use: "recover", Short: "Restore a temporary Windows protocol handler left after an interrupted login", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		unlock, e := store.Lock(filepath.Join(dir, "callback-lock"))
		if e != nil {
			return e
		}
		defer unlock()
		if e = auth.Recover(dir); e != nil {
			return e
		}
		_ = os.Remove(filepath.Join(dir, "callback-session.json"))
		fmt.Fprintln(cmd.OutOrStdout(), "Protocol recovery completed.")
		return nil
	}})

	listNetworks := func(cmd *cobra.Command, args []string) error {
		p, e := a.LoadReady(profile)
		if e != nil {
			return e
		}
		n, e := a.API.Networks(cmd.Context(), p.AccountID, p.DeviceID, p.AccessToken)
		if e != nil {
			return e
		}
		for _, v := range n.Networks {
			mark := " "
			if v.ID == n.Selected {
				mark = "*"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s\t%s\n", mark, v.Name, v.ID)
		}
		return nil
	}
	selectNetwork := func(cmd *cobra.Command, args []string) error {
		v, e := a.SelectVNet(cmd.Context(), profile, args[0])
		if e != nil {
			return e
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Selected and verified VNET %s (%s). Reconnect the WireGuard/usque client.\n", v.Name, v.ID)
		return nil
	}
	vnets := &cobra.Command{Use: "vnet [name-or-UUID]", Short: "List VNETs, or select a VNET for this registration", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return listNetworks(cmd, args)
		}
		return selectNetwork(cmd, args)
	}}
	vnets.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: listNetworks})
	vnets.AddCommand(&cobra.Command{Use: "use <name-or-UUID>", Args: cobra.ExactArgs(1), RunE: selectNetwork})
	root.AddCommand(vnets)

	var offline, genOffline bool
	status := func(cmd *cobra.Command, name string, offline bool) error {
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
		if !offline {
			if _, e = a.LoadReady(name); e != nil {
				return e
			}
			if e = a.Refresh(cmd.Context(), p); e != nil {
				return e
			}
			n, e := a.API.Networks(cmd.Context(), p.AccountID, p.DeviceID, p.AccessToken)
			if e != nil {
				return e
			}
			p.SelectedVNet = n.Selected
			if e = a.Store.Save(p); e != nil {
				return e
			}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Profile: %s\nTeam: %s\nDevice: %s\nName: %s\nProtocol: %s\nState: %s\nSelected VNET: %s\n", p.Name, p.Team, p.DeviceID, p.Registration.Name, p.Protocol, p.State, p.SelectedVNet)
		if offline {
			fmt.Fprintln(cmd.OutOrStdout(), "Source: local cache")
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "Source: live registration API (not a tunnel connectivity test)")
		}
		return nil
	}
	sc := &cobra.Command{Use: "status", Short: "Check saved registration, remote key/protocol, and selected VNET", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error { return status(cmd, profile, offline) }}
	sc.Flags().BoolVar(&offline, "offline", false, "Show local state without contacting Cloudflare")
	root.AddCommand(sc)

	var format, output string
	var mtu, keepalive int
	var dns, allowed []string
	gen := &cobra.Command{Use: "generate", Aliases: []string{"config"}, Short: "Generate a WireGuard profile or usque JSON for this registration", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		d, e := a.Store.ProfileDir(profile)
		if e != nil {
			return e
		}
		unlock, e := store.Lock(d)
		if e != nil {
			return e
		}
		defer unlock()
		p, e := a.LoadReady(profile)
		if e != nil {
			return e
		}
		if !genOffline {
			if e = a.Refresh(cmd.Context(), p); e != nil {
				return e
			}
			n, e := a.API.Networks(cmd.Context(), p.AccountID, p.DeviceID, p.AccessToken)
			if e != nil {
				return e
			}
			p.SelectedVNet = n.Selected
			if e = a.Store.Save(p); e != nil {
				return e
			}
		}
		path, e := a.Export(p, app.ExportOptions{Format: format, Output: output, MTU: mtu, Keepalive: keepalive, DNS: dns, AllowedIPs: allowed})
		if e != nil {
			return e
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Configuration:", path)
		return nil
	}}
	gen.Flags().StringVar(&format, "format", "", "wireguard or usque (defaults to profile protocol)")
	gen.Flags().StringVarP(&output, "output", "o", "", "Output path; default is inside the named profile")
	gen.Flags().IntVar(&mtu, "mtu", 1280, "WireGuard MTU")
	gen.Flags().IntVar(&keepalive, "keepalive", 25, "WireGuard keepalive in seconds, 0 disables")
	gen.Flags().StringSliceVar(&dns, "dns", nil, "Comma-separated DNS IPs; omitted by default")
	gen.Flags().StringSliceVar(&allowed, "allowed-ips", nil, "WireGuard CIDRs; defaults to 0.0.0.0/0,::/0")
	gen.Flags().BoolVar(&genOffline, "offline", false, "Use cached registration without refreshing")
	root.AddCommand(gen)

	var yes bool
	dereg := &cobra.Command{Use: "dereg", Aliases: []string{"deregister"}, Short: "Delete this remote registration and clear its local credentials", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		p, e := a.Store.Load(profile)
		if e != nil {
			return e
		}
		if !yes {
			fmt.Fprintf(cmd.OutOrStdout(), "Delete device %s? Type the profile name (%s): ", p.DeviceID, profile)
			s, e := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
			if e != nil && s == "" {
				return e
			}
			if strings.TrimSpace(s) != profile {
				return fmt.Errorf("deletion cancelled")
			}
		}
		if e = a.Deregister(cmd.Context(), profile); e != nil {
			return e
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Device registration deleted; local credentials cleared. External configuration copies are not removed.")
		return nil
	}}
	dereg.Flags().BoolVar(&yes, "yes", false, "Confirm deletion without prompting")
	root.AddCommand(dereg)

	devices := &cobra.Command{Use: "devices", Short: "Manage device registrations owned by local profiles"}
	devices.AddCommand(&cobra.Command{Use: "list", Short: "List local profiles without exposing credentials", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		entries, e := os.ReadDir(filepath.Join(dir, "profiles"))
		if os.IsNotExist(e) {
			return nil
		}
		if e != nil {
			return e
		}
		for _, x := range entries {
			if !x.IsDir() {
				continue
			}
			p, e := a.Store.Load(x.Name())
			if e != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Cannot load profile %s\n", x.Name())
				continue
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\t%s\n", p.Name, p.Team, p.Protocol, p.State, p.DeviceID)
		}
		return nil
	}})
	devices.AddCommand(&cobra.Command{Use: "show [profile]", Short: "Fetch live status for a locally managed device", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		name := profile
		if len(args) > 0 {
			name = args[0]
		}
		return status(cmd, name, false)
	}})
	devices.AddCommand(&cobra.Command{Use: "rename <display-name>", Short: "Rename the device selected by --profile", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if len(args[0]) == 0 || len(args[0]) > 128 {
			return fmt.Errorf("device name must be 1-128 bytes")
		}
		d, e := a.Store.ProfileDir(profile)
		if e != nil {
			return e
		}
		unlock, e := store.Lock(d)
		if e != nil {
			return e
		}
		defer unlock()
		p, e := a.LoadReady(profile)
		if e != nil {
			return e
		}
		if e = a.API.Do(cmd.Context(), "PATCH", api.RegPath(p.DeviceID), p.AccessToken, "", map[string]string{"name": args[0]}, nil); e != nil {
			return e
		}
		if e = a.Refresh(cmd.Context(), p); e != nil {
			return e
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Device name:", p.Registration.Name)
		return nil
	}})
	root.AddCommand(devices)

	var registrationFile, keyFile, importTeam string
	imp := &cobra.Command{Use: "import", Short: "Import a WireGuard registration JSON and local private-key file", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if _, e := auth.TeamHost(importTeam); e != nil {
			return e
		}
		if registrationFile == "" || keyFile == "" {
			return fmt.Errorf("--registration and --key-file are required")
		}
		d, e := a.Store.ProfileDir(profile)
		if e != nil {
			return e
		}
		unlock, e := store.Lock(d)
		if e != nil {
			return e
		}
		defer unlock()
		if _, e = os.Stat(filepath.Join(d, "account.json")); e == nil {
			return fmt.Errorf("profile already exists")
		} else if !os.IsNotExist(e) {
			return e
		}
		b, e := os.ReadFile(registrationFile)
		if e != nil {
			return e
		}
		var r api.Registration
		if json.Unmarshal(b, &r) != nil {
			return fmt.Errorf("invalid registration JSON")
		}
		b, e = os.ReadFile(keyFile)
		if e != nil {
			return e
		}
		key := strings.TrimSpace(string(b))
		var obj struct {
			Private string `json:"private_key"`
		}
		if json.Unmarshal(b, &obj) == nil && obj.Private != "" {
			key = obj.Private
		}
		pub, e := app.WGPublic(key)
		if e != nil {
			return e
		}
		if r.ID == "" || r.Token == "" || r.Account.ID == "" || r.Key != pub || r.TunnelType != "wireguard" {
			return fmt.Errorf("registration and key do not describe the same WireGuard device")
		}
		p := &store.Profile{Name: profile, Team: importTeam, Protocol: "wireguard", State: "ready", DeviceID: r.ID, AccountID: r.Account.ID, AccessToken: r.Token, WGPrivateKey: key, Registration: r}
		if e = a.Store.Save(p); e != nil {
			return e
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Imported profile:", profile)
		return nil
	}}
	imp.Flags().StringVar(&registrationFile, "registration", "", "Registration response JSON file")
	imp.Flags().StringVar(&keyFile, "key-file", "", "Base64 private key file or JSON with private_key")
	imp.Flags().StringVar(&importTeam, "team", "", "Organization slug")
	root.AddCommand(imp)
	return root
}
