# go-security-headers

Security-headers middleware for Go HTTP servers, for both Gin and the standard `net/http`. Requires Go 1.25 (per `go.mod`).

## Installation

```bash
go get github.com/ralvarezdev/go-security-headers
```

## Headers set

Both middlewares add these response headers:

- **`X-Frame-Options`** — `DENY`
- **`Content-Security-Policy`** — `default-src 'self'; connect-src *; font-src *; script-src-elem * 'unsafe-inline'; img-src * data:; style-src * 'unsafe-inline';`
- **`X-XSS-Protection`** — `1; mode=block`
- **`Strict-Transport-Security`** — `max-age=31536000; includeSubDomains; preload`
- **`Referrer-Policy`** — `strict-origin`
- **`X-Content-Type-Options`** — `nosniff`
- **`Permissions-Policy`** — `geolocation=(),midi=(),sync-xhr=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()`

The values are hard-coded; there is no configuration API. The Content-Security-Policy is fairly permissive (wildcard sources, inline scripts and styles allowed), so review it for your application.

## Usage

```go
// Gin (package gin)
r := gin.New()
r.Use(gosecurityheadersgin.HandlerFunc())

// net/http (package net/http)
mux := http.NewServeMux()
http.ListenAndServe(":8080", gosecurityheadershttp.Handler(mux))
```

Imports: `github.com/ralvarezdev/go-security-headers/gin` and `github.com/ralvarezdev/go-security-headers/net/http`.

## Development

```bash
go build ./...
```

There are no tests.

## License

GNU General Public License v3.0 (see [LICENSE](LICENSE)).
