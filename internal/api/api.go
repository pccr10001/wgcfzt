package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const BaseURL = "https://api.cloudflareclient.com"
const Version = "v0a4471"

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New() *Client {
	return &Client{BaseURL: BaseURL, HTTP: &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

type APIError struct {
	Status int
	Codes  []int
}

func (e *APIError) Error() string {
	return fmt.Sprintf("WARP API returned HTTP %d (codes %v); registration, user session, and policy failures must be distinguished", e.Status, e.Codes)
}

// Errors intentionally omit response bodies and request headers, which can contain credentials.
func (c *Client) Do(ctx context.Context, method, path, token, jwt string, payload, out any) error {
	var data io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		data = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, data)
	if err != nil {
		return fmt.Errorf("create API request: %w", err)
	}
	req.Header.Set("User-Agent", "WARP for Android")
	req.Header.Set("CF-Client-Version", "a-6.35-4471")
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if jwt != "" {
		req.Header.Set("CF-Access-Jwt-Assertion", jwt)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("read API response: %w", err)
	}
	var envelope struct {
		Success *bool `json:"success"`
		Errors  []struct {
			Code int `json:"code"`
		} `json:"errors"`
	}
	_ = json.Unmarshal(b, &envelope)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || (envelope.Success != nil && !*envelope.Success) {
		e := &APIError{Status: resp.StatusCode}
		for _, x := range envelope.Errors {
			e.Codes = append(e.Codes, x.Code)
		}
		return e
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("API returned an unexpected JSON response")
		}
	}
	return nil
}

type Peer struct {
	PublicKey string `json:"public_key"`
	Endpoint  struct {
		V4    string `json:"v4"`
		V6    string `json:"v6"`
		Host  string `json:"host"`
		Ports []int  `json:"ports"`
	} `json:"endpoint"`
}
type Registration struct {
	ID         string `json:"id"`
	Token      string `json:"token,omitempty"`
	Key        string `json:"key"`
	KeyType    string `json:"key_type"`
	TunnelType string `json:"tunnel_type"`
	Name       string `json:"name"`
	Account    struct {
		ID           string `json:"id"`
		Organization string `json:"organization"`
	} `json:"account"`
	Config struct {
		ClientID  string `json:"client_id"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []Peer `json:"peers"`
	} `json:"config"`
	Policy json.RawMessage `json:"policy,omitempty"`
}
type Network struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Comment string `json:"comment"`
	Default bool   `json:"is_default_network"`
}
type Networks struct {
	Selected string    `json:"selected_virtual_network_id"`
	Networks []Network `json:"virtual_networks"`
}

func RegPath(id string) string { return "/" + Version + "/reg/" + url.PathEscape(id) }
func VNetPath(account, device string) string {
	return "/v0/accounts/" + url.PathEscape(account) + "/reg/" + url.PathEscape(device) + "/virtualnetworks"
}
func (c *Client) Get(ctx context.Context, id, token string) (Registration, error) {
	var r Registration
	err := c.Do(ctx, "GET", RegPath(id), token, "", nil, &r)
	return r, err
}
func (c *Client) Networks(ctx context.Context, account, id, token string) (Networks, error) {
	var r struct {
		Success bool     `json:"success"`
		Result  Networks `json:"result"`
	}
	err := c.Do(ctx, "GET", VNetPath(account, id), token, "", nil, &r)
	if err == nil && !r.Success {
		err = fmt.Errorf("VNET listing was not accepted")
	}
	return r.Result, err
}
func (c *Client) Select(ctx context.Context, account, id, token, vnet string) error {
	var r struct {
		Success bool `json:"success"`
	}
	if err := c.Do(ctx, "PATCH", VNetPath(account, id)+"/"+url.PathEscape(vnet), token, "", nil, &r); err != nil {
		return err
	}
	if !r.Success {
		return fmt.Errorf("VNET selection was not accepted")
	}
	return nil
}
