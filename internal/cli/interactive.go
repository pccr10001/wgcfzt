package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/pccr10001/wgcfzt/internal/app"
	"github.com/pccr10001/wgcfzt/internal/store"
	"github.com/spf13/cobra"
)

var errCancelled = errors.New("operation cancelled")

type prompts struct {
	cmd    *cobra.Command
	reader *bufio.Reader
}

func newPrompts(cmd *cobra.Command) *prompts {
	r := bufio.NewReader(cmd.InOrStdin())
	cmd.SetIn(r)
	return &prompts{cmd, r}
}
func (p *prompts) line(label, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(p.cmd.OutOrStdout(), "%s [%s]: ", label, def)
	} else {
		fmt.Fprint(p.cmd.OutOrStdout(), label+": ")
	}
	type result struct {
		s string
		e error
	}
	ch := make(chan result, 1)
	go func() { s, e := p.reader.ReadString('\n'); ch <- result{s, e} }()
	select {
	case <-p.cmd.Context().Done():
		return "", p.cmd.Context().Err()
	case r := <-ch:
		if r.e != nil && r.s == "" {
			return "", fmt.Errorf("interactive input ended; supply command flags or use --non-interactive: %w", r.e)
		}
		s := strings.TrimSpace(r.s)
		if s == "q" {
			return "", errCancelled
		}
		if s == "" {
			s = def
		}
		return s, nil
	}
}
func (p *prompts) choose(title string, labels []string, selected int) (int, error) {
	if len(labels) == 0 {
		return 0, fmt.Errorf("no available choices")
	}
	fmt.Fprintln(p.cmd.OutOrStdout(), "\n"+title)
	for i, label := range labels {
		mark := " "
		if i == selected {
			mark = "*"
		}
		fmt.Fprintf(p.cmd.OutOrStdout(), "  %s %d) %s\n", mark, i+1, display(label))
	}
	for {
		def := ""
		if selected >= 0 {
			def = strconv.Itoa(selected + 1)
		}
		s, e := p.line("Choose a number, q cancels", def)
		if e != nil {
			return 0, e
		}
		n, e := strconv.Atoi(s)
		if e == nil && n >= 1 && n <= len(labels) {
			return n - 1, nil
		}
		fmt.Fprintln(p.cmd.OutOrStdout(), "Enter a number from the list.")
	}
}
func (p *prompts) confirm(label string) (bool, error) {
	s, e := p.line(label+" (y/N)", "n")
	return strings.EqualFold(s, "y") || strings.EqualFold(s, "yes"), e
}
func display(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

type deviceRow struct {
	Profile      *store.Profile
	VNet, Source string
}

func localProfiles(s store.Store) ([]*store.Profile, error) {
	entries, e := os.ReadDir(filepath.Join(s.Dir, "profiles"))
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var result []*store.Profile
	for _, x := range entries {
		if !x.IsDir() {
			continue
		}
		p, e := s.Load(x.Name())
		if e != nil {
			return nil, e
		}
		result = append(result, p)
	}
	return result, nil
}
func deviceRows(ctx context.Context, a *app.App, live bool) ([]deviceRow, error) {
	profiles, e := localProfiles(a.Store)
	if e != nil {
		return nil, e
	}
	rows := make([]deviceRow, 0, len(profiles))
	for _, p := range profiles {
		vnet := p.SelectedVNetName
		if vnet == "" {
			vnet = p.SelectedVNet
		}
		if vnet == "" {
			vnet = "-"
		}
		row := deviceRow{p, vnet, "cached"}
		if live && p.State == "ready" {
			n, e := a.API.Networks(ctx, p.AccountID, p.DeviceID, p.AccessToken)
			if e != nil {
				row.Source = "API unavailable"
			} else {
				row.Source = "live"
				row.VNet = n.Selected
				for _, v := range n.Networks {
					if v.ID == n.Selected {
						row.VNet = v.Name
					}
				}
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}
func printDevices(cmd *cobra.Command, rows []deviceRow) {
	if len(rows) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No devices found. Run wgcfzt reg.")
		return
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "DEVICE\tTEAM\tPROTOCOL\tSTATE\tVNET\tSOURCE")
	for _, r := range rows {
		p := r.Profile
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", display(p.Name), display(p.Team), p.Protocol, p.State, display(r.VNet), r.Source)
	}
	w.Flush()
}
func resolveDevice(s store.Store, selector string) (string, error) {
	profiles, e := localProfiles(s)
	if e != nil {
		return "", e
	}
	var matches []string
	for _, p := range profiles {
		if p.Name == selector || p.DeviceID == selector {
			matches = append(matches, p.Name)
		}
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("--device must identify one locally managed device by name or device ID")
	}
	return matches[0], nil
}
func chooseDevice(cmd *cobra.Command, a *app.App, readyOnly, live bool) (string, error) {
	rows, e := deviceRows(cmd.Context(), a, live)
	if e != nil {
		return "", e
	}
	var choices []deviceRow
	var labels []string
	for _, r := range rows {
		if r.Profile.State == "deregistered" || (readyOnly && r.Profile.State != "ready") {
			continue
		}
		choices = append(choices, r)
		labels = append(labels, fmt.Sprintf("%s | %s | %s | VNET: %s", r.Profile.Name, r.Profile.Protocol, r.Profile.State, r.VNet))
	}
	if len(choices) == 0 {
		return "", fmt.Errorf("no eligible devices; run wgcfzt reg first")
	}
	i, e := newPrompts(cmd).choose("Select device", labels, 0)
	if e != nil {
		return "", e
	}
	return choices[i].Profile.Name, nil
}
func chooseVNet(cmd *cobra.Command, a *app.App, name string) (string, error) {
	p, e := a.LoadReady(name)
	if e != nil {
		return "", e
	}
	n, e := a.API.Networks(cmd.Context(), p.AccountID, p.DeviceID, p.AccessToken)
	if e != nil {
		return "", e
	}
	labels := make([]string, len(n.Networks))
	selected := -1
	for i, v := range n.Networks {
		labels[i] = v.Name + "  " + v.ID
		if v.ID == n.Selected {
			selected = i
		}
	}
	i, e := newPrompts(cmd).choose("Select VNET for "+name, labels, selected)
	if e != nil {
		return "", e
	}
	return n.Networks[i].ID, nil
}
func nextDeviceName(s store.Store) string {
	for i := 1; ; i++ {
		name := "default"
		if i > 1 {
			name = fmt.Sprintf("device-%d", i)
		}
		_, e := s.Load(name)
		if errors.Is(e, os.ErrNotExist) {
			return name
		}
		if e != nil {
			return "new-device"
		}
	}
}
func suggestedTeam(s store.Store) string {
	p, e := localProfiles(s)
	if e != nil || len(p) == 0 {
		return ""
	}
	team := p[0].Team
	for _, x := range p {
		if x.Team != team {
			return ""
		}
	}
	return team
}
