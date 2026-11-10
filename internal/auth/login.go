package auth

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/pccr10001/wgcfzt/internal/store"
)

type Options struct {
	Team, Dir, Browser string
	Manual             bool
	Timeout            time.Duration
	In                 io.Reader
	Out                io.Writer
}
type session struct {
	URL   string `json:"url"`
	Nonce string `json:"nonce"`
	Team  string `json:"team"`
}

var ErrRecoveryRequired = errors.New("a previous protocol takeover needs recovery")
var installHandler = takeover
var launchBrowser = openBrowser

func sessionPath(dir string) string { return filepath.Join(dir, "callback-session.json") }

// Login always restores the protocol before returning a token to the caller.
func Login(ctx context.Context, o Options) (token string, err error) {
	host, err := TeamHost(o.Team)
	if err != nil {
		return "", err
	}
	if _, e := os.Stat(filepath.Join(o.Dir, "protocol-backup.json")); e == nil {
		return "", fmt.Errorf("run wgcfzt recover before logging in: %w", ErrRecoveryRequired)
	} else if !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	if o.Manual {
		return manual(ctx, o)
	}
	if e := checkBrowser(o.Browser); e != nil {
		fmt.Fprintln(o.Out, "Automatic callback unavailable:", e)
		return manual(ctx, o)
	}
	unlock, err := store.Lock(filepath.Join(o.Dir, "callback-lock"))
	if err != nil {
		return "", err
	}
	defer unlock()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer listener.Close()
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return "", err
	}
	s := session{URL: "http://" + listener.Addr().String() + "/callback", Nonce: hex.EncodeToString(nonce[:]), Team: o.Team}
	if err = store.WriteJSON(sessionPath(o.Dir), s); err != nil {
		return "", err
	}
	defer os.Remove(sessionPath(o.Dir))
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	restore, err := installHandler(o.Dir, exe)
	if err != nil {
		if _, statErr := os.Stat(filepath.Join(o.Dir, "protocol-backup.json")); statErr == nil || errors.Is(err, ErrRecoveryRequired) {
			return "", fmt.Errorf("run wgcfzt recover before logging in: %w", err)
		}
		fmt.Fprintln(o.Out, "Automatic callback unavailable:", err)
		return manual(ctx, o)
	}
	// A restoration failure is fatal: never proceed to register with the handler still installed.
	defer func() {
		if e := restore(); e != nil {
			token = ""
			err = errors.Join(err, fmt.Errorf("restore protocol failed; run wgcfzt recover: %w", e))
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	tokens := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.Nonce)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		b, e := io.ReadAll(io.LimitReader(r.Body, 32769))
		if e != nil || len(b) > 32768 {
			http.Error(w, "invalid callback", 400)
			return
		}
		t, e := ParseToken(string(b), o.Team)
		if e != nil {
			http.Error(w, "invalid callback", 400)
			return
		}
		select {
		case tokens <- t:
			w.WriteHeader(204)
		default:
			http.Error(w, "callback already received", 409)
		}
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	defer server.Close()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	loginURL := "https://" + host + "/warp"
	fmt.Fprintln(o.Out, "Temporary callback installed. Opening organization sign-in; the original handler will be restored before registration.")
	fmt.Fprintln(o.Out, "On the success page, open the callback with wgcfzt if prompted. Do not select the original WARP application.")
	if e := launchBrowser(o.Browser, loginURL); e != nil {
		fmt.Fprintln(o.Out, "Open this URL in your browser:", loginURL)
	}
	select {
	case token = <-tokens:
		return token, nil
	case <-ctx.Done():
		return "", fmt.Errorf("login ended: %w; retry with --manual if the browser did not deliver the callback", ctx.Err())
	case e := <-serveErr:
		return "", fmt.Errorf("callback listener ended: %w", e)
	}
}

func manual(ctx context.Context, o Options) (string, error) {
	host, err := TeamHost(o.Team)
	if err != nil {
		return "", err
	}
	fmt.Fprintln(o.Out, "Manual login: paste the WARP JWT or full callback URL below. No native handler will be invoked by this tool.")
	fmt.Fprintln(o.Out, "In Firefox, after signing into your organization, view source to copy the callback without executing it:")
	fmt.Fprintln(o.Out, "view-source:https://"+host+"/warp")
	fmt.Fprintln(o.Out, "Do not approve opening the original WARP app. Paste token/callback, then Enter:")
	if o.Browser == "firefox" {
		_ = launchBrowser("firefox", "view-source:https://"+host+"/warp")
	}
	type result struct {
		s string
		e error
	}
	ch := make(chan result, 1)
	go func() {
		// Reuse the CLI reader so pasted input for the following VNET prompt
		// remains available after reading the callback.
		reader := bufio.NewReader(o.In)
		var input []byte
		for {
			part, e := reader.ReadSlice('\n')
			if len(input)+len(part) > 32768 {
				ch <- result{"", fmt.Errorf("JWT input too large")}
				return
			}
			input = append(input, part...)
			if e != bufio.ErrBufferFull {
				ch <- result{string(input), e}
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	select {
	case r := <-ch:
		if r.e != nil && r.s == "" {
			return "", fmt.Errorf("read pasted token: %w", r.e)
		}
		return ParseToken(r.s, o.Team)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Deliver runs in a short-lived process started by the OS protocol association.
func Deliver(ctx context.Context, dir, callback string) error {
	b, err := os.ReadFile(sessionPath(dir))
	if err != nil {
		return fmt.Errorf("no active wgcfzt login session")
	}
	var s session
	if json.Unmarshal(b, &s) != nil {
		return fmt.Errorf("invalid callback session")
	}
	if _, err = ParseToken(callback, s.Team); err != nil {
		return err
	}
	// Session files must never direct credentials to a non-loopback URL.
	u, err := parseLoopback(s.URL)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewBufferString(callback))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.Nonce)
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("callback delivery failed")
	}
	defer r.Body.Close()
	if r.StatusCode != 204 {
		return fmt.Errorf("callback rejected (HTTP %d)", r.StatusCode)
	}
	return nil
}
