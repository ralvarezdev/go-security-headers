package http

import (
	"net/http"
)

// Handler adds security headers to the response
//
// Parameters:
//
//   - next: the next handler to be called
//
// Returns:
//
//   - http.Handler: the handler with security headers
func Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// Add security headers
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set(
				"Content-Security-Policy",
				"default-src 'self'; connect-src *; font-src *; script-src-elem * 'unsafe-inline'; img-src * data:; style-src * 'unsafe-inline';",
			)
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set(
				"Strict-Transport-Security",
				"max-age=31536000; includeSubDomains; preload",
			)
			w.Header().Set("Referrer-Policy", "strict-origin")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set(
				"Permissions-Policy",
				"geolocation=(),midi=(),sync-xhr=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()",
			)

			// Serve the next handler
			next.ServeHTTP(w, r)
		},
	)
}
