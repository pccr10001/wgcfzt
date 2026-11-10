package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var teamPattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

func TeamHost(team string) (string, error) {
	if !teamPattern.MatchString(team) {
		return "", fmt.Errorf("--team must be the organization slug, without a URL")
	}
	return strings.ToLower(team) + ".cloudflareaccess.com", nil
}

// ParseToken accepts a pasted JWT or full native callback. It does not authenticate
// the JWT signature: Cloudflare verifies it during registration.
func ParseToken(input, team string) (string, error) {
	host, err := TeamHost(team)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(input)
	if strings.HasPrefix(s, "com.cloudflare.warp:") {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("invalid callback URL")
		}
		if u.Scheme != "com.cloudflare.warp" || !strings.EqualFold(u.Host, host) || u.Path != "/auth" || u.User != nil || u.Fragment != "" {
			return "", fmt.Errorf("callback does not match the requested organization")
		}
		s = u.Query().Get("token")
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("paste the WARP JWT or complete com.cloudflare.warp:// callback")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid JWT payload")
	}
	var claims struct {
		Issuer string `json:"iss"`
		Exp    int64  `json:"exp"`
		Nbf    int64  `json:"nbf"`
	}
	if json.Unmarshal(b, &claims) != nil {
		return "", fmt.Errorf("invalid JWT payload")
	}
	if claims.Issuer != "https://"+host && claims.Issuer != "https://"+host+"/" {
		return "", fmt.Errorf("JWT issuer does not match --team")
	}
	if claims.Exp <= time.Now().Unix() {
		return "", fmt.Errorf("login JWT has expired; sign in again")
	}
	if claims.Nbf > time.Now().Add(time.Minute).Unix() {
		return "", fmt.Errorf("login JWT is not valid yet; check the system clock")
	}
	return s, nil
}
