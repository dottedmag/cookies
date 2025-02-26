# Go library for declaring cookies by programmer's intent
[![Go Reference](https://pkg.go.dev/badge/github.com/dottedmag/cookies.svg)](https://pkg.go.dev/github.com/dottedmag/cookies)

`cookies.Intent` describes programmer's intent of declaring a cookie:

    cookie := cookies.Compile(cookies.Intent{
        Name: "__Host-ID",
        Value: "12345",
        Expires: cookies.ExpiresAfter(24*time.Hour),
    }

This will create a cookie with secure defaults:
 - scoped to the current domain (not revealed to subdomains) and https-only
 - with default cross-site Cookie setting (allow cross-site requests only on navigation)
 - not revealed to JavaScript

To reveal cookie to JavaScript, add `RevealToJavaScript: true`.

For other customizations, see the documentation for `Intent` struct.

## Legal

Licensed under [MIT](LICENSE) license.
