package auth

import (
	"fmt"
	"net/url"
)

func parseLoopback(s string) (string, error) {
	u, e := url.Parse(s)
	if e != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path != "/callback" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid loopback callback address")
	}
	return u.String(), nil
}
