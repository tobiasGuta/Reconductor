package normalize

import (
	"reflect"
	"testing"
)

func TestURLNormalization(t *testing.T) {
	got, err := URL("HTTPS://Example.COM:443/a/../b?z=2&a=1#frag")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.com/b?a=1&z=2" {
		t.Fatalf("got %s", got)
	}
}
func TestRouteDedupOnlyDynamicSegments(t *testing.T) {
	legitimate := []string{"users", "admin", "billing", "payments"}
	for _, p := range legitimate {
		k, err := Endpoint("https://example.com/api/"+p, "GET", "application/json")
		if err != nil {
			t.Fatal(err)
		}
		if k.RouteSignature != "/api/"+p {
			t.Fatalf("legitimate path collapsed: %s", k.RouteSignature)
		}
	}
	dynamic := []string{"123", "550e8400-e29b-41d4-a716-446655440000", "507f1f77bcf86cd799439011", "2026-07-21", "aB9_x7K2pQ4-rT8z"}
	for _, p := range dynamic {
		k, _ := Endpoint("https://example.com/items/"+p, "GET", "")
		if k.RouteSignature != "/items/{id}" {
			t.Errorf("%q was not generalized: %s", p, k.RouteSignature)
		}
	}
}
func TestEndpointIdentityPreservesMethodContentTypeAndParameterNames(t *testing.T) {
	a, _ := Endpoint("https://example.com/api?id=1&q=x", "GET", "application/json; charset=utf-8")
	b, _ := Endpoint("https://example.com/api?id=2&q=y", "GET", "application/json")
	if a.Digest != b.Digest {
		t.Fatal("query values should normalize")
	}
	c, _ := Endpoint("https://example.com/api?id=2&q=y", "POST", "application/json")
	if a.Digest == c.Digest {
		t.Fatal("method must affect identity")
	}
	d, _ := Endpoint("https://example.com/api?id=2", "GET", "application/json")
	if a.Digest == d.Digest {
		t.Fatal("parameter schema must affect identity")
	}
}

func TestCanonicalEndpointOriginNormalization(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		exact     string
		origin    EndpointOrigin
		wantError bool
	}{
		{name: "ASCII reg-name and terminal dot", raw: "HTTPS://API_EXAMPLE.COM./x", exact: "https://api_example.com./x", origin: EndpointOrigin{Scheme: "https", Host: "api_example.com.", EffectivePort: 443}},
		{name: "empty interior labels", raw: "https://a..b/x", exact: "https://a..b/x", origin: EndpointOrigin{Scheme: "https", Host: "a..b", EffectivePort: 443}},
		{name: "punycode remains literal", raw: "https://XN--BCHER-KVA.example/x", exact: "https://xn--bcher-kva.example/x", origin: EndpointOrigin{Scheme: "https", Host: "xn--bcher-kva.example", EffectivePort: 443}},
		{name: "IPv4", raw: "http://192.168.1.1:80/x", exact: "http://192.168.1.1/x", origin: EndpointOrigin{Scheme: "http", Host: "192.168.1.1", EffectivePort: 80}},
		{name: "IPv6", raw: "http://[2001:0DB8::1]:80/x", exact: "http://[2001:db8::1]/x", origin: EndpointOrigin{Scheme: "http", Host: "2001:db8::1", EffectivePort: 80}},
		{name: "mapped IPv6 is not unmapped", raw: "https://[::ffff:192.0.2.1]/x", exact: "https://[::ffff:192.0.2.1]/x", origin: EndpointOrigin{Scheme: "https", Host: "::ffff:192.0.2.1", EffectivePort: 443}},
		{name: "non-default port", raw: "https://example.com:8443/x", exact: "https://example.com:8443/x", origin: EndpointOrigin{Scheme: "https", Host: "example.com", EffectivePort: 8443}},
		{name: "absolute required", raw: "example.com/x", wantError: true},
		{name: "scheme rejected", raw: "ftp://example.com/x", wantError: true},
		{name: "Unicode host rejected", raw: "https://bücher.example/x", wantError: true},
		{name: "percent host rejected", raw: "https://exa%6dple.example/x", wantError: true},
		{name: "userinfo rejected", raw: "https://user@example.com/x", wantError: true},
		{name: "empty userinfo rejected", raw: "https://@example.com/x", wantError: true},
		{name: "ambiguous IPv4 rejected", raw: "http://192.168.001.1/x", wantError: true},
		{name: "short IPv4 rejected", raw: "http://127.1/x", wantError: true},
		{name: "numeric terminal dot rejected", raw: "http://192.168.1.1./x", wantError: true},
		{name: "IPv6 zone rejected", raw: "http://[fe80::1%25eth0]/x", wantError: true},
		{name: "IPvFuture rejected", raw: "http://[v1.fe]/x", wantError: true},
		{name: "empty port rejected", raw: "http://example.com:/x", wantError: true},
		{name: "signed port rejected", raw: "http://example.com:+80/x", wantError: true},
		{name: "zero port rejected", raw: "http://example.com:0/x", wantError: true},
		{name: "large port rejected", raw: "http://example.com:65536/x", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, origin, err := CanonicalEndpoint(test.raw, "GET", "")
			if test.wantError {
				if err == nil {
					t.Fatalf("CanonicalEndpoint(%q) succeeded: key=%#v origin=%#v", test.raw, key, origin)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if key.ExactURL != test.exact || origin != test.origin {
				t.Fatalf("key=%#v origin=%#v", key, origin)
			}
		})
	}
}

func TestCanonicalEndpointPreservesSecuritySignificantPathStructure(t *testing.T) {
	tests := []struct {
		raw, exact, route string
	}{
		{raw: "https://example.com", exact: "https://example.com/", route: "/"},
		{raw: "https://example.com/a//b", exact: "https://example.com/a//b", route: "/a//b"},
		{raw: "https://example.com/a/./b", exact: "https://example.com/a/./b", route: "/a/./b"},
		{raw: "https://example.com/a/../b", exact: "https://example.com/a/../b", route: "/a/../b"},
		{raw: "https://example.com/a/", exact: "https://example.com/a/", route: "/a/"},
		{raw: "https://example.com/a%20b", exact: "https://example.com/a%20b", route: "/a%20b"},
		{raw: "https://example.com/a%25b", exact: "https://example.com/a%25b", route: "/a%25b"},
		{raw: "https://example.com/a%2fb", exact: "https://example.com/a%2Fb", route: "/a%2Fb"},
		{raw: "https://example.com/a/%2e/b", exact: "https://example.com/a/%2E/b", route: "/a/%2E/b"},
		{raw: "https://example.com/a/%2e%2e/b", exact: "https://example.com/a/%2E%2E/b", route: "/a/%2E%2E/b"},
		{raw: "https://example.com/items/%31%32%33", exact: "https://example.com/items/%31%32%33", route: "/items/{id}"},
	}
	for _, test := range tests {
		key, _, err := CanonicalEndpoint(test.raw, "GET", "")
		if err != nil {
			t.Fatalf("%s: %v", test.raw, err)
		}
		if key.ExactURL != test.exact || key.RouteSignature != test.route {
			t.Errorf("%s: exact=%q route=%q", test.raw, key.ExactURL, key.RouteSignature)
		}
		again, _, err := CanonicalEndpoint(key.ExactURL, key.Method, key.ContentType)
		if err != nil || !reflect.DeepEqual(again, key) {
			t.Errorf("%s is not idempotent: again=%#v err=%v", test.raw, again, err)
		}
	}

	distinct := [][2]string{{"/a/b", "/a//b"}, {"/a/b", "/a/./b"}, {"/b", "/a/../b"}, {"/a", "/a/"}, {"/a/b", "/a%2Fb"}}
	for _, pair := range distinct {
		left, _, _ := CanonicalEndpoint("https://example.com"+pair[0], "GET", "")
		right, _, _ := CanonicalEndpoint("https://example.com"+pair[1], "GET", "")
		if left.Digest == right.Digest {
			t.Errorf("paths %q and %q collapsed", pair[0], pair[1])
		}
	}
}

func TestCanonicalEndpointQueryAndDigestFraming(t *testing.T) {
	a, _, err := CanonicalEndpoint("https://example.com/api?b=2&a=1&a=3", "get", "Application/JSON; charset=utf-8")
	if err != nil {
		t.Fatal(err)
	}
	if a.ExactURL != "https://example.com/api?a=1&a=3&b=2" || a.Method != "GET" || a.ContentType != "application/json" || !reflect.DeepEqual(a.QueryParameters, []string{"a", "b"}) {
		t.Fatalf("canonical endpoint=%#v", a)
	}
	b, _, _ := CanonicalEndpoint("https://example.com/api?b=other&a=value", "GET", "application/json")
	if a.Digest != b.Digest {
		t.Fatal("query values changed identity")
	}
	commaLeft, _, _ := CanonicalEndpoint("https://example.com/api?a%2Cb=1&c=1", "GET", "")
	commaRight, _, _ := CanonicalEndpoint("https://example.com/api?a=1&b%2Cc=1", "GET", "")
	if commaLeft.Digest == commaRight.Digest {
		t.Fatal("query parameter JSON framing is ambiguous")
	}
	if _, _, err := CanonicalEndpoint("https://example.com/api?bad=%zz", "GET", ""); err == nil {
		t.Fatal("malformed query escape was accepted")
	}
}

func TestCanonicalEndpointOriginAffectsIdentity(t *testing.T) {
	inputs := []string{
		"https://a.example/api/users",
		"https://b.example/api/users",
		"http://a.example/api/users",
		"https://a.example:8443/api/users",
	}
	seen := map[string]bool{}
	for _, raw := range inputs {
		key, _, err := CanonicalEndpoint(raw, "GET", "")
		if err != nil {
			t.Fatal(err)
		}
		if seen[key.Digest] {
			t.Fatalf("origin identity collapsed for %s", raw)
		}
		seen[key.Digest] = true
	}
	omitted, _, _ := CanonicalEndpoint("https://a.example/api/users", "GET", "")
	explicit, _, _ := CanonicalEndpoint("https://a.example:443/api/users", "GET", "")
	if omitted.Digest != explicit.Digest || omitted.ExactURL != explicit.ExactURL {
		t.Fatal("default port forms did not normalize together")
	}
}
