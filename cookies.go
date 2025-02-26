package cookies

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Source describes allowed request sources for a browser to send a cookie
type Source string

// Source values directly correspond to SameSite cookie attributes, but have
// descriptive names and values
const (
	SameSite                Source = "A->A"
	SameSiteOrAnySiteByUser Source = "A->A,*-(user)->A"
	AnySite                 Source = "*->A"
)

// Expiration describes cookie expiration limits
type Expiration struct {
	Session bool
	At      time.Time
	After   time.Duration
}

// WhenUAIsClosed is predefined expiration value
var WhenUAIsClosed = Expiration{Session: true}

// At creates expiration at specified moment
func At(t time.Time) Expiration {
	return Expiration{At: t}
}

// After creates expiration after specified duration
func After(d time.Duration) Expiration {
	return Expiration{After: d}
}

// Immediately creates immediate expiration
func Immediately() Expiration {
	return Expiration{After: -time.Second}
}

// Intent is a description of a browser cookie.
type Intent struct {
	Name    string
	Value   string
	Expires Expiration

	// ReturnTo specifies the web page to which the browser should return the cookie.
	// It has the form <schema>://<host><path>.
	//   Schema: https | https?
	//   Host: **.foobar.com | <current>
	//   Path: /**, /foobar**, /foobar/**
	//
	// This field defaults to the most restrictive "https://<current>/**"
	ReturnTo string

	ReturnOnNavigationFrom Source
	RevealToJavaScript     bool
}

func parseReturnTo(returnTo string) (retSecure bool, retDomain, retPath string, _ error) {
	if returnTo == "" {
		return true, "", "/", nil
	}

	schema, rest, ok := strings.Cut(returnTo, "://")
	if !ok {
		return false, "", "", fmt.Errorf("%q is not in form ...://...", returnTo)
	}

	var secure bool
	switch schema {
	case "https":
		secure = true
	case "https?":
		secure = false
	default:
		return false, "", "", fmt.Errorf("%q schema is not https or https?", returnTo)
	}

	domain, path, ok := strings.Cut(rest, "/")
	if !ok {
		return false, "", "", fmt.Errorf("%q is not in form ...://.../...", returnTo)
	}

	if domain == "<current>" {
		domain = ""
	} else {
		if !strings.HasPrefix(domain, "**.") {
			return false, "", "", fmt.Errorf("%q has explicit domain without **.", returnTo)
		}
		domain = strings.TrimPrefix(domain, "**.")
		if strings.HasPrefix(domain, ".") {
			return false, "", "", fmt.Errorf("domain should not have form **..example.com")
		}
	}

	if !strings.HasSuffix(path, "**") {
		return false, "", "", fmt.Errorf("%q is not in form ...://.../...**", returnTo)
	}
	path = strings.TrimSuffix(path, "**")
	if path == "" {
		path = "/"
	}
	return secure, domain, path, nil
}

// Compile transforms an Intent into an http.Cookie.
func Compile(i Intent) (*http.Cookie, error) {
	if i.Expires.After != 0 && !i.Expires.At.IsZero() {
		return nil, fmt.Errorf("Expires.After and Expires.At are mutually exclusive")
	}

	secure, domain, path, err := parseReturnTo(i.ReturnTo)
	if err != nil {
		return nil, err
	}

	var expires time.Time
	var maxAge int
	switch {
	case !i.Expires.At.IsZero():
		expires = i.Expires.At
	case i.Expires.After != 0:
		maxAge = int(i.Expires.After.Seconds())
	case i.Expires.Session:
	default:
		return nil, fmt.Errorf("At least one of WhenUAIsClosed, At, After, or Immediately needs to be set")
	}

	if strings.HasPrefix(i.Name, "__Secure-") && !secure {
		return nil, fmt.Errorf("Cookies named __Secure-* must use schema https:")
	}
	if strings.HasPrefix(i.Name, "__Host-") && (!secure || domain != "" || path != "/") {
		return nil, fmt.Errorf("Cookies named __Host-* must have ReturnTo https://<current>/**")
	}

	var sameSite http.SameSite
	switch i.ReturnOnNavigationFrom {
	case SameSite:
		sameSite = http.SameSiteStrictMode
	case SameSiteOrAnySiteByUser, "":
		sameSite = http.SameSiteLaxMode
	case AnySite:
		sameSite = http.SameSiteNoneMode
	default:
		return nil, fmt.Errorf("unsupported ReturnOnNavigationFrom value %q", i.ReturnOnNavigationFrom)
	}

	if !secure && sameSite == http.SameSiteNoneMode {
		return nil, fmt.Errorf("cookie with SameSite=None must be secure")
	}

	cookie := &http.Cookie{
		Name:     i.Name,
		Value:    i.Value,
		Domain:   domain,
		Path:     path,
		Expires:  expires,
		MaxAge:   maxAge,
		Secure:   secure,
		HttpOnly: !i.RevealToJavaScript,
		SameSite: sameSite,
	}

	if err := cookie.Valid(); err != nil {
		return nil, err
	}

	return cookie, nil
}
