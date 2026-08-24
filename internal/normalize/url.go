package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	uuid     = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hexID    = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	date     = regexp.MustCompile(`^\d{4}[-/]\d{2}[-/]\d{2}(?:T\d{2}:\d{2}(?::\d{2})?Z?)?$`)
	objectID = regexp.MustCompile(`(?i)^[0-9a-f]{24}$`)
)

type EndpointKey struct {
	ExactURL        string   `json:"exact_url"`
	RouteSignature  string   `json:"route_signature"`
	Method          string   `json:"method"`
	ContentType     string   `json:"content_type"`
	QueryParameters []string `json:"query_parameters"`
	Digest          string   `json:"digest"`
}

type EndpointOrigin struct {
	Scheme        string
	Host          string
	EffectivePort int
}

func URL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + strings.TrimPrefix(raw, "//")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("URL has no host")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	u.Host = host
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	}
	u.Fragment = ""
	u.Path = path.Clean("/" + strings.TrimPrefix(u.EscapedPath(), "/"))
	if u.Path == "/." {
		u.Path = "/"
	}
	u.RawPath = ""
	u.RawQuery = u.Query().Encode()
	return u.String(), nil
}

func Endpoint(rawURL, method, contentType string) (EndpointKey, error) {
	key, _, err := CanonicalEndpoint(rawURL, method, contentType)
	return key, err
}

func CanonicalEndpoint(rawURL, method, contentType string) (EndpointKey, EndpointOrigin, error) {
	u, origin, err := endpointURL(rawURL)
	if err != nil {
		return EndpointKey{}, EndpointOrigin{}, err
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return EndpointKey{}, EndpointOrigin{}, fmt.Errorf("parse endpoint query: %w", err)
	}
	u.RawQuery = values.Encode()
	u.ForceQuery = false
	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	sort.Strings(names)
	sig := route(u.EscapedPath())
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	contentType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	material, err := json.Marshal([]any{origin.Scheme, origin.Host, origin.EffectivePort, sig, method, contentType, names})
	if err != nil {
		return EndpointKey{}, EndpointOrigin{}, fmt.Errorf("encode endpoint identity: %w", err)
	}
	sum := sha256.Sum256([]byte(material))
	return EndpointKey{ExactURL: u.String(), RouteSignature: sig, Method: method, ContentType: contentType, QueryParameters: names, Digest: hex.EncodeToString(sum[:])}, origin, nil
}

func endpointURL(raw string) (*url.URL, EndpointOrigin, error) {
	raw = strings.TrimSpace(raw)
	separator := strings.Index(raw, "://")
	if separator <= 0 {
		return nil, EndpointOrigin{}, fmt.Errorf("endpoint URL must be absolute HTTP or HTTPS")
	}
	scheme := strings.ToLower(raw[:separator])
	if scheme != "http" && scheme != "https" {
		return nil, EndpointOrigin{}, fmt.Errorf("unsupported endpoint URL scheme %q", raw[:separator])
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, EndpointOrigin{}, err
	}
	if u.Opaque != "" || u.Host == "" || strings.ToLower(u.Scheme) != scheme {
		return nil, EndpointOrigin{}, fmt.Errorf("endpoint URL must be absolute HTTP or HTTPS")
	}
	if u.User != nil {
		return nil, EndpointOrigin{}, fmt.Errorf("endpoint URL userinfo is not allowed")
	}
	origin, err := normalizeEndpointOrigin(scheme, u.Host)
	if err != nil {
		return nil, EndpointOrigin{}, err
	}
	escapedPath := u.EscapedPath()
	if escapedPath == "" {
		escapedPath = "/"
	}
	if !strings.HasPrefix(escapedPath, "/") {
		return nil, EndpointOrigin{}, fmt.Errorf("endpoint URL path must be absolute")
	}
	escapedPath, err = uppercaseEscapes(escapedPath)
	if err != nil {
		return nil, EndpointOrigin{}, err
	}
	decodedPath, err := url.PathUnescape(escapedPath)
	if err != nil {
		return nil, EndpointOrigin{}, fmt.Errorf("decode endpoint path: %w", err)
	}
	u.Scheme = origin.Scheme
	u.Host = renderEndpointAuthority(origin)
	u.Path = decodedPath
	u.RawPath = ""
	if u.EscapedPath() != escapedPath {
		u.RawPath = escapedPath
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u, origin, nil
}

func normalizeEndpointOrigin(scheme, authority string) (EndpointOrigin, error) {
	if strings.Contains(authority, "%") {
		return EndpointOrigin{}, fmt.Errorf("endpoint host percent encoding and IPv6 zones are not allowed")
	}
	bracketed := strings.HasPrefix(authority, "[")
	host := ""
	portText := ""
	explicitPort := false
	if bracketed {
		closing := strings.LastIndex(authority, "]")
		if closing <= 1 {
			return EndpointOrigin{}, fmt.Errorf("endpoint IPv6 host is invalid")
		}
		host = authority[1:closing]
		suffix := authority[closing+1:]
		if suffix != "" {
			if !strings.HasPrefix(suffix, ":") {
				return EndpointOrigin{}, fmt.Errorf("endpoint IPv6 authority is invalid")
			}
			explicitPort = true
			portText = strings.TrimPrefix(suffix, ":")
		}
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is6() {
			return EndpointOrigin{}, fmt.Errorf("endpoint IPv6 host is invalid")
		}
		host = address.String()
	} else {
		if strings.Count(authority, ":") > 1 {
			return EndpointOrigin{}, fmt.Errorf("endpoint IPv6 host must be bracketed")
		}
		host = authority
		if separator := strings.LastIndexByte(authority, ':'); separator >= 0 {
			explicitPort = true
			host, portText = authority[:separator], authority[separator+1:]
		}
		if host == "" {
			return EndpointOrigin{}, fmt.Errorf("endpoint URL has no host")
		}
		if digitsAndDots(host) {
			address, err := netip.ParseAddr(host)
			if err != nil || !address.Is4() {
				return EndpointOrigin{}, fmt.Errorf("endpoint IPv4 host is ambiguous or invalid")
			}
			host = address.String()
		} else {
			if err := validateEndpointRegName(host); err != nil {
				return EndpointOrigin{}, err
			}
			host = strings.ToLower(host)
		}
	}
	defaultPort := 80
	if scheme == "https" {
		defaultPort = 443
	}
	port := defaultPort
	if explicitPort {
		if portText == "" {
			return EndpointOrigin{}, fmt.Errorf("endpoint port is empty")
		}
		for _, character := range portText {
			if character < '0' || character > '9' {
				return EndpointOrigin{}, fmt.Errorf("endpoint port must be decimal")
			}
		}
		parsed, err := strconv.Atoi(portText)
		if err != nil || parsed < 1 || parsed > 65535 {
			return EndpointOrigin{}, fmt.Errorf("endpoint port is outside 1-65535")
		}
		port = parsed
	}
	return EndpointOrigin{Scheme: scheme, Host: host, EffectivePort: port}, nil
}

func validateEndpointRegName(host string) error {
	for index := 0; index < len(host); index++ {
		character := host[index]
		if character >= 0x80 || !endpointRegNameCharacter(character) {
			return fmt.Errorf("endpoint host is not an ASCII reg-name")
		}
	}
	return nil
}

func endpointRegNameCharacter(character byte) bool {
	if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
		return true
	}
	return strings.ContainsRune("-._~!$&'()*+,;=", rune(character))
}

func digitsAndDots(host string) bool {
	if host == "" {
		return false
	}
	for _, character := range host {
		if character != '.' && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func renderEndpointAuthority(origin EndpointOrigin) string {
	defaultPort := 80
	if origin.Scheme == "https" {
		defaultPort = 443
	}
	if origin.EffectivePort != defaultPort {
		return net.JoinHostPort(origin.Host, strconv.Itoa(origin.EffectivePort))
	}
	if strings.Contains(origin.Host, ":") {
		return "[" + origin.Host + "]"
	}
	return origin.Host
}

func uppercaseEscapes(value string) (string, error) {
	var builder strings.Builder
	builder.Grow(len(value))
	for index := 0; index < len(value); index++ {
		if value[index] != '%' {
			builder.WriteByte(value[index])
			continue
		}
		if index+2 >= len(value) || !hexDigit(value[index+1]) || !hexDigit(value[index+2]) {
			return "", fmt.Errorf("endpoint path contains an invalid percent escape")
		}
		builder.WriteByte('%')
		builder.WriteByte(upperHex(value[index+1]))
		builder.WriteByte(upperHex(value[index+2]))
		index += 2
	}
	return builder.String(), nil
}

func hexDigit(character byte) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F'
}

func upperHex(character byte) byte {
	if character >= 'a' && character <= 'f' {
		return character - ('a' - 'A')
	}
	return character
}

func route(p string) string {
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, s := range segs {
		if s != "" && dynamic(s) {
			segs[i] = "{id}"
		}
	}
	return "/" + strings.Join(segs, "/")
}
func dynamic(s string) bool {
	decoded, err := url.PathUnescape(s)
	if err == nil {
		s = decoded
	}
	if uuid.MatchString(s) || objectID.MatchString(s) || hexID.MatchString(s) || date.MatchString(s) {
		return true
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n >= 0 {
		return true
	}
	if len(s) >= 16 {
		classes := 0
		if regexp.MustCompile(`[a-z]`).MatchString(s) {
			classes++
		}
		if regexp.MustCompile(`[A-Z]`).MatchString(s) {
			classes++
		}
		if regexp.MustCompile(`[0-9]`).MatchString(s) {
			classes++
		}
		if regexp.MustCompile(`[-_]`).MatchString(s) {
			classes++
		}
		return classes >= 3
	}
	return false
}
