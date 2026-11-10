package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestErrorRedactionAndNoRedirect(t *testing.T) {
	for _, status := range []int{200, 401, 403, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "https://example.com/leak")
				w.WriteHeader(status)
				fmt.Fprint(w, `{"success":false,"token":"private-body","errors":[{"code":1001}]}`)
			}))
			defer s.Close()
			c := New()
			c.BaseURL = s.URL
			e := c.Do(context.Background(), "GET", "/reg/test", "private-bearer", "private-jwt", nil, nil)
			if e == nil {
				t.Fatal("accepted failed/redirected request")
			}
			for _, secret := range []string{"private-body", "private-bearer", "private-jwt"} {
				if strings.Contains(e.Error(), secret) {
					t.Fatal("secret leaked")
				}
			}
		})
	}
}
