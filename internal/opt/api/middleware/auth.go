package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

type AuthMiddleware struct {
	Token string
}

func (m AuthMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.Token == "" {
			http.Error(w, "internal auth token is not configured", http.StatusServiceUnavailable)
			return
		}

		got := r.Header.Get("Authorization")
		const prefix = "Bearer "

		if !strings.HasPrefix(got, prefix) {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		gotToken := strings.TrimPrefix(got, prefix)

		if subtle.ConstantTimeCompare([]byte(gotToken), []byte(m.Token)) != 1 {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
