package provideroutput

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Kind string

const (
	HostRecord Kind = "host"
	PortRecord Kind = "port"
	URLRecord  Kind = "url"
)

type Record struct {
	Provider     string         `json:"provider"`
	Kind         Kind           `json:"kind"`
	Target       string         `json:"target"`
	Host         string         `json:"host,omitempty"`
	Port         int            `json:"port,omitempty"`
	StatusCode   int            `json:"status_code,omitempty"`
	Technologies []string       `json:"technologies,omitempty"`
	Fields       map[string]any `json:"fields,omitempty"`
}

type Warning struct {
	Line   int    `json:"line"`
	Reason string `json:"reason"`
}

type Batch struct {
	Records  []Record  `json:"records"`
	Warnings []Warning `json:"warnings"`
}

func Parse(provider string, lines []string) Batch {
	batch := Batch{Records: []Record{}, Warnings: []Warning{}}
	for i, line := range lines {
		record, err := parseOne(strings.ToLower(provider), strings.TrimSpace(line))
		if err != nil {
			batch.Warnings = append(batch.Warnings, Warning{Line: i + 1, Reason: err.Error()})
			continue
		}
		batch.Records = append(batch.Records, record)
	}
	return batch
}

func parseOne(provider, line string) (Record, error) {
	if line == "" {
		return Record{}, fmt.Errorf("empty record")
	}
	switch provider {
	case "subfinder", "chaos":
		host, err := plainOrStringField(line, "host", "name", "domain")
		if err != nil {
			return Record{}, err
		}
		return hostRecord(provider, host)
	case "dnsx":
		host, err := plainOrStringField(line, "host", "input", "name")
		if err != nil {
			return Record{}, err
		}
		return hostRecord(provider, host)
	case "naabu":
		return parseNaabu(line)
	case "httpx":
		return parseURLJSON(provider, line, "url", "final-url", "input")
	case "katana":
		return parseKatana(line)
	case "gau":
		return parseURLJSON(provider, line, "url")
	case "nuclei":
		return parseURLJSON(provider, line, "matched-at", "matched", "url")
	default:
		return Record{}, fmt.Errorf("unsupported provider adapter %q", provider)
	}
}

func hostRecord(provider, raw string) (Record, error) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if net.ParseIP(host) == nil {
		if len(host) == 0 || strings.ContainsAny(host, " /:@") {
			return Record{}, fmt.Errorf("invalid hostname")
		}
		for _, label := range strings.Split(host, ".") {
			if label == "" {
				return Record{}, fmt.Errorf("invalid hostname")
			}
		}
	}
	return Record{Provider: provider, Kind: HostRecord, Target: host, Host: host}, nil
}

func parseNaabu(line string) (Record, error) {
	if v, err := decodeJSONObject(line); err == nil {
		host := firstString(v, "host", "ip", "input")
		port, present, err := firstInt(v, "port")
		if err != nil {
			return Record{}, fmt.Errorf("invalid naabu port")
		}
		if host == "" || !present {
			return Record{}, fmt.Errorf("naabu record requires host and port")
		}
		return portObservation("naabu", host, port, v)
	}
	host, rawPort, ok := strings.Cut(line, ":")
	if !ok {
		return Record{}, fmt.Errorf("invalid naabu record")
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		return Record{}, fmt.Errorf("invalid naabu port")
	}
	return portObservation("naabu", host, port, nil)
}

func portObservation(provider, host string, port int, fields map[string]any) (Record, error) {
	h, err := hostRecord(provider, host)
	if err != nil {
		return Record{}, err
	}
	if port < 1 || port > 65535 {
		return Record{}, fmt.Errorf("invalid port")
	}
	return Record{Provider: provider, Kind: PortRecord, Target: net.JoinHostPort(h.Host, strconv.Itoa(port)), Host: h.Host, Port: port, Fields: fields}, nil
}

func parseKatana(line string) (Record, error) {
	v, err := decodeJSONObject(line)
	if err != nil {
		return parseURLValue("katana", line, nil)
	}
	raw := firstString(v, "url", "endpoint")
	if request, ok := v["request"].(map[string]any); ok && raw == "" {
		raw = firstString(request, "endpoint", "url")
	}
	return parseURLValue("katana", raw, v)
}

func parseURLJSON(provider, line string, keys ...string) (Record, error) {
	if v, err := decodeJSONObject(line); err == nil {
		raw := firstString(v, keys...)
		if raw == "" && provider == "httpx" {
			host, scheme := firstString(v, "host", "input"), firstString(v, "scheme")
			if scheme != "" && host != "" {
				raw = scheme + "://" + host
			}
		}
		record, err := parseURLValue(provider, raw, v)
		if err == nil {
			status, present, statusErr := firstInt(v, "status_code", "status-code", "status")
			if statusErr != nil || present && (status < 100 || status > 599) {
				return Record{}, fmt.Errorf("invalid HTTP status code")
			}
			if present {
				record.StatusCode = status
			}
			record.Technologies = stringSlice(v["tech"])
			if len(record.Technologies) == 0 {
				record.Technologies = stringSlice(v["technologies"])
			}
		}
		return record, err
	}
	return parseURLValue(provider, line, nil)
}

func parseURLValue(provider, raw string, fields map[string]any) (Record, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return Record{}, fmt.Errorf("invalid HTTP URL")
	}
	u.Fragment = ""
	return Record{Provider: provider, Kind: URLRecord, Target: u.String(), Host: strings.ToLower(u.Hostname()), Fields: fields}, nil
}

func plainOrStringField(line string, keys ...string) (string, error) {
	if v, err := decodeJSONObject(line); err == nil {
		return firstString(v, keys...), nil
	} else {
		trimmed := strings.TrimSpace(line)
		if trimmed == "null" || strings.HasPrefix(trimmed, "{") {
			return "", err
		}
	}
	return line, nil
}
func firstString(v map[string]any, keys ...string) string {
	for _, key := range keys {
		if s, ok := v[key].(string); ok {
			return s
		}
	}
	return ""
}
func firstInt(v map[string]any, keys ...string) (int, bool, error) {
	for _, key := range keys {
		raw, present := v[key]
		if !present {
			continue
		}
		switch n := raw.(type) {
		case json.Number:
			if value, ok := ExactJSONInteger(n.String()); ok {
				return value, true, nil
			}
		case string:
			value, err := strconv.Atoi(n)
			if err == nil {
				return value, true, nil
			}
		}
		return 0, true, fmt.Errorf("field %s is not an exact integer", key)
	}
	return 0, false, nil
}

const (
	maxExactIntegerTokenLength = 64
	maxExactIntegerDigits      = 32
	maxExactIntegerExponent    = 64
)

// ExactJSONInteger parses the integral JSON forms used by bounded provider
// domains without expanding attacker-controlled arbitrary-precision values.
func ExactJSONInteger(raw string) (int, bool) {
	if raw == "" || len(raw) > maxExactIntegerTokenLength {
		return 0, false
	}
	index := 0
	negative := false
	if raw[index] == '-' {
		negative = true
		index++
		if index == len(raw) {
			return 0, false
		}
	}
	digits := make([]byte, 0, min(len(raw), maxExactIntegerDigits))
	if raw[index] == '0' {
		digits = append(digits, '0')
		index++
		if index < len(raw) && raw[index] >= '0' && raw[index] <= '9' {
			return 0, false
		}
	} else if raw[index] >= '1' && raw[index] <= '9' {
		for index < len(raw) && raw[index] >= '0' && raw[index] <= '9' {
			digits = append(digits, raw[index])
			index++
		}
	} else {
		return 0, false
	}
	fractionDigits := 0
	if index < len(raw) && raw[index] == '.' {
		index++
		fractionStart := index
		for index < len(raw) && raw[index] >= '0' && raw[index] <= '9' {
			digits = append(digits, raw[index])
			fractionDigits++
			index++
		}
		if index == fractionStart {
			return 0, false
		}
	}
	if len(digits) > maxExactIntegerDigits {
		return 0, false
	}
	exponent := 0
	if index < len(raw) && (raw[index] == 'e' || raw[index] == 'E') {
		index++
		exponentNegative := false
		if index < len(raw) && (raw[index] == '+' || raw[index] == '-') {
			exponentNegative = raw[index] == '-'
			index++
		}
		exponentStart := index
		exponentDigits := 0
		for index < len(raw) && raw[index] >= '0' && raw[index] <= '9' {
			exponentDigits++
			if exponentDigits > 3 {
				return 0, false
			}
			exponent = exponent*10 + int(raw[index]-'0')
			if exponent > maxExactIntegerExponent {
				return 0, false
			}
			index++
		}
		if index == exponentStart {
			return 0, false
		}
		if exponentNegative {
			exponent = -exponent
		}
	}
	if index != len(raw) {
		return 0, false
	}
	firstNonZero := 0
	for firstNonZero < len(digits) && digits[firstNonZero] == '0' {
		firstNonZero++
	}
	if firstNonZero == len(digits) {
		return 0, true
	}
	digits = digits[firstNonZero:]
	scale := exponent - fractionDigits
	if scale < 0 {
		remove := -scale
		if remove > len(digits) {
			return 0, false
		}
		for _, digit := range digits[len(digits)-remove:] {
			if digit != '0' {
				return 0, false
			}
		}
		digits = digits[:len(digits)-remove]
	} else if scale > 0 {
		if len(digits)+scale > 19 {
			return 0, false
		}
		digits = append(digits, strings.Repeat("0", scale)...)
	}
	if len(digits) == 0 {
		return 0, true
	}
	integer := string(digits)
	if negative {
		integer = "-" + integer
	}
	value, err := strconv.ParseInt(integer, 10, 64)
	if err != nil {
		return 0, false
	}
	if int64(int(value)) != value {
		return 0, false
	}
	return int(value), true
}
func stringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func decodeJSONObject(raw string) (map[string]any, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple JSON values")
		}
		return nil, err
	}
	if value == nil {
		return nil, fmt.Errorf("JSON object is required")
	}
	return value, nil
}
