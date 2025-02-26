package cookies

import (
	"net/http"
	"testing"
	"time"
)

func assertOK(t *testing.T, name string, intent Intent, expected *http.Cookie) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		t.Helper()
		got, err := Compile(intent)

		if err != nil {
			t.Errorf("Compile() unexpected error: %v", err)
			return
		}

		if got.Name != expected.Name {
			t.Errorf("Cookie.Name = %q, want %q", got.Name, expected.Name)
		}
		if got.Value != expected.Value {
			t.Errorf("Cookie.Value = %q, want %q", got.Value, expected.Value)
		}
		if got.Path != expected.Path {
			t.Errorf("Cookie.Path = %q, want %q", got.Path, expected.Path)
		}
		if got.Domain != expected.Domain {
			t.Errorf("Cookie.Domain = %q, want %q", got.Domain, expected.Domain)
		}
		if got.MaxAge != expected.MaxAge {
			t.Errorf("Cookie.MaxAge = %d, want %d", got.MaxAge, expected.MaxAge)
		}
		if expected.Expires.Unix() > 0 && !got.Expires.Equal(expected.Expires) {
			t.Errorf("Cookie.Expires = %v, want %v", got.Expires, expected.Expires)
		}
		if got.Secure != expected.Secure {
			t.Errorf("Cookie.Secure = %v, want %v", got.Secure, expected.Secure)
		}
		if got.HttpOnly != expected.HttpOnly {
			t.Errorf("Cookie.HttpOnly = %v, want %v", got.HttpOnly, expected.HttpOnly)
		}
		if got.SameSite != expected.SameSite {
			t.Errorf("Cookie.SameSite = %v, want %v", got.SameSite, expected.SameSite)
		}
	})
}

func assertError(t *testing.T, name string, intent Intent) {
	t.Run(name, func(t *testing.T) {
		_, err := Compile(intent)

		if err == nil {
			t.Errorf("Compile() expected error but got nil")
		}
	})
}

func TestCompile(t *testing.T) {
	var testTime = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)

	// Success cases
	assertOK(t, "basic cookie",
		Intent{
			Name:    "test",
			Value:   "value",
			Expires: After(24 * time.Hour),
		},
		&http.Cookie{
			Name:     "test",
			Value:    "value",
			Path:     "/",
			MaxAge:   86400,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

	assertOK(t, "cookie with expiration time",
		Intent{
			Name:    "test",
			Value:   "value",
			Expires: At(testTime),
		},
		&http.Cookie{
			Name:     "test",
			Value:    "value",
			Path:     "/",
			Expires:  testTime,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

	assertOK(t, "cookie revealed to JavaScript",
		Intent{
			Name:               "test",
			Value:              "value",
			Expires:            After(24 * time.Hour),
			RevealToJavaScript: true,
		},
		&http.Cookie{
			Name:     "test",
			Value:    "value",
			Path:     "/",
			MaxAge:   86400,
			Secure:   true,
			HttpOnly: false,
			SameSite: http.SameSiteLaxMode,
		})

	assertOK(t, "__Host- prefixed cookie",
		Intent{
			Name:    "__Host-test",
			Value:   "value",
			Expires: After(24 * time.Hour),
		},
		&http.Cookie{
			Name:     "__Host-test",
			Value:    "value",
			Path:     "/",
			MaxAge:   86400,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

	assertOK(t, "__Secure- prefixed cookie",
		Intent{
			Name:    "__Secure-test",
			Value:   "value",
			Expires: After(24 * time.Hour),
		},
		&http.Cookie{
			Name:     "__Secure-test",
			Value:    "value",
			Path:     "/",
			MaxAge:   86400,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

	assertOK(t, "strict same-site",
		Intent{
			Name:                   "test",
			Value:                  "value",
			Expires:                After(24 * time.Hour),
			ReturnOnNavigationFrom: SameSite,
		},
		&http.Cookie{
			Name:     "test",
			Value:    "value",
			Path:     "/",
			MaxAge:   86400,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

	assertOK(t, "any-site navigation",
		Intent{
			Name:                   "test",
			Value:                  "value",
			Expires:                After(24 * time.Hour),
			ReturnOnNavigationFrom: AnySite,
		},
		&http.Cookie{
			Name:     "test",
			Value:    "value",
			Path:     "/",
			MaxAge:   86400,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteNoneMode,
		})

	assertOK(t, "documentation example",
		Intent{
			Name:    "__Host-ID",
			Value:   "12345",
			Expires: After(24 * time.Hour),
		},
		&http.Cookie{
			Name:     "__Host-ID",
			Value:    "12345",
			Path:     "/",
			MaxAge:   86400,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

	assertOK(t, "session cookie",
		Intent{
			Name:    "session-cookie",
			Value:   "value",
			Expires: WhenUAIsClosed,
		},
		&http.Cookie{
			Name:     "session-cookie",
			Value:    "value",
			Path:     "/",
			MaxAge:   0,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

	assertOK(t, "immediate expiration",
		Intent{
			Name:    "expired-cookie",
			Value:   "value",
			Expires: Immediately(),
		},
		&http.Cookie{
			Name:     "expired-cookie",
			Value:    "value",
			Path:     "/",
			MaxAge:   0,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

	// Error cases
	assertError(t, "invalid: conflicting expiration",
		Intent{
			Name:    "test",
			Value:   "value",
			Expires: Expiration{At: testTime, After: 24 * time.Hour},
		})

	assertError(t, "invalid: missing expiration",
		Intent{
			Name:  "test",
			Value: "value",
		})

	assertError(t, "invalid: __Host- with domain",
		Intent{
			Name:     "__Host-test",
			Value:    "value",
			Expires:  After(24 * time.Hour),
			ReturnTo: "https://**.example.com/**",
		})

	assertError(t, "invalid: __Host- with non-root path",
		Intent{
			Name:     "__Host-test",
			Value:    "value",
			Expires:  After(24 * time.Hour),
			ReturnTo: "https://<current>/foo/**",
		})

	assertError(t, "invalid: __Secure- with insecure",
		Intent{
			Name:     "__Secure-test",
			Value:    "value",
			Expires:  After(24 * time.Hour),
			ReturnTo: "https?://<current>/**",
		})

	assertError(t, "invalid: SameSite=None with insecure",
		Intent{
			Name:                   "test",
			Value:                  "value",
			Expires:                After(24 * time.Hour),
			ReturnTo:               "https?://<current>/**",
			ReturnOnNavigationFrom: AnySite,
		})

	assertError(t, "invalid: invalid ReturnOnNavigationFrom value",
		Intent{
			Name:                   "test",
			Value:                  "value",
			Expires:                After(24 * time.Hour),
			ReturnOnNavigationFrom: Source("invalid"),
		})

	assertError(t, "invalid: invalid cookie value",
		Intent{
			Name:    "test",
			Value:   "щ", // Invalid character in cookie value
			Expires: After(24 * time.Hour),
		})

	assertError(t, "invalid ReturnTo: wrong syntax",
		Intent{
			Name:     "test",
			Value:    "value",
			Expires:  After(24 * time.Hour),
			ReturnTo: "http:/**.example.com/**",
		})

	assertError(t, "invalid ReturnTo: invalid schema",
		Intent{
			Name:     "test",
			Value:    "value",
			Expires:  After(24 * time.Hour),
			ReturnTo: "http://**.example.com/**",
		})

	assertError(t, "invalid ReturnTo: missing path separator",
		Intent{
			Name:     "test",
			Value:    "value",
			Expires:  After(24 * time.Hour),
			ReturnTo: "https://example.com",
		})

	assertError(t, "invalid ReturnTo: explicit domain without ** prefix",
		Intent{
			Name:     "test",
			Value:    "value",
			Expires:  After(24 * time.Hour),
			ReturnTo: "https://example.com/**",
		})

	assertError(t, "invalid ReturnTo: invalid domain format",
		Intent{
			Name:     "test",
			Value:    "value",
			Expires:  After(24 * time.Hour),
			ReturnTo: "https://**.example.com.**/**",
		})

	assertError(t, "invalid ReturnTo: path without ** suffix",
		Intent{
			Name:     "test",
			Value:    "value",
			Expires:  After(24 * time.Hour),
			ReturnTo: "https://<current>/foo",
		})

	assertError(t, "invalid ReturnTo: double dot in domain",
		Intent{
			Name:     "test",
			Value:    "value",
			Expires:  After(24 * time.Hour),
			ReturnTo: "https://**..example.com/**",
		})
}
