package canonicaljson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ParseStrict decodes exactly one UTF-8 JSON value, rejects duplicate object
// member names at every depth, and returns both its canonical representation
// and the frozen value-node/depth measurements.
func ParseStrict(raw []byte) (any, []byte, uint64, uint64, error) {
	return parseStrict(raw, 0)
}

// ParseStrictBounded requires a pre-bounded input and refuses canonical output
// growth before writing beyond maxBytes (including numeric/escape expansion).
func ParseStrictBounded(raw []byte, maxBytes int) (any, []byte, uint64, uint64, error) {
	if maxBytes < 1 || len(raw) > maxBytes {
		return nil, nil, 0, 0, &EncodingLimitError{Limit: maxBytes}
	}
	return parseStrict(raw, maxBytes)
}

func parseStrict(raw []byte, maxBytes int) (any, []byte, uint64, uint64, error) {
	if !utf8.Valid(raw) {
		return nil, nil, 0, 0, fmt.Errorf("JSON is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, nodes, depth, err := decodeStrictValue(decoder, 1)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		if err == nil {
			return nil, nil, 0, 0, fmt.Errorf("multiple JSON values")
		}
		return nil, nil, 0, 0, fmt.Errorf("trailing JSON: %w", err)
	}
	var canonical []byte
	if maxBytes == 0 {
		canonical, err = Marshal(value)
	} else {
		out := &boundedEncoding{limit: maxBytes}
		err = appendValue(out, value)
		canonical = out.Bytes()
	}
	if err != nil {
		return nil, nil, 0, 0, err
	}
	return value, canonical, nodes, depth, nil
}

func decodeStrictValue(decoder *json.Decoder, depth uint64) (any, uint64, uint64, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, 0, 0, err
	}
	delim, composite := token.(json.Delim)
	if !composite {
		switch token.(type) {
		case nil, bool, string, json.Number:
			return token, 1, depth, nil
		default:
			return nil, 0, 0, fmt.Errorf("unsupported JSON token %T", token)
		}
	}

	nodes, maximum := uint64(1), depth
	switch delim {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return nil, 0, 0, err
			}
			name, ok := nameToken.(string)
			if !ok {
				return nil, 0, 0, fmt.Errorf("object member name is not a string")
			}
			if _, exists := object[name]; exists {
				return nil, 0, 0, fmt.Errorf("duplicate object member %q", name)
			}
			child, childNodes, childDepth, err := decodeStrictValue(decoder, depth+1)
			if err != nil {
				return nil, 0, 0, err
			}
			if ^uint64(0)-nodes < childNodes {
				return nil, 0, 0, fmt.Errorf("JSON node count overflow")
			}
			nodes += childNodes
			if childDepth > maximum {
				maximum = childDepth
			}
			object[name] = child
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return nil, 0, 0, fmt.Errorf("object is incomplete")
		}
		return object, nodes, maximum, nil
	case '[':
		array := []any{}
		for decoder.More() {
			child, childNodes, childDepth, err := decodeStrictValue(decoder, depth+1)
			if err != nil {
				return nil, 0, 0, err
			}
			if ^uint64(0)-nodes < childNodes {
				return nil, 0, 0, fmt.Errorf("JSON node count overflow")
			}
			nodes += childNodes
			if childDepth > maximum {
				maximum = childDepth
			}
			array = append(array, child)
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return nil, 0, 0, fmt.Errorf("array is incomplete")
		}
		return array, nodes, maximum, nil
	default:
		return nil, 0, 0, fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

// Marshal encodes JSON-compatible values deterministically. Callers with Go
// structs should marshal them to json.RawMessage first so numbers are decoded
// with json.Number rather than lossy floating-point values.
func Marshal(value any) ([]byte, error) {
	var out bytes.Buffer
	if err := appendValue(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// MarshalBounded encodes an already byte-admitted value with an incremental
// output ceiling. RawMessage members are checked before whole-value decoding.
func MarshalBounded(value any, maxBytes int) ([]byte, error) {
	if maxBytes < 1 {
		return nil, &EncodingLimitError{Limit: maxBytes}
	}
	out := &boundedEncoding{limit: maxBytes}
	if err := appendValue(out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

type encodingWriter interface {
	Write([]byte) (int, error)
	WriteString(string) (int, error)
	WriteByte(byte) error
}

type EncodingLimitError struct{ Limit int }

func (e *EncodingLimitError) Error() string {
	return fmt.Sprintf("canonical JSON exceeds %d bytes", e.Limit)
}

type boundedEncoding struct {
	bytes.Buffer
	limit int
	err   error
}

func (b *boundedEncoding) allow(n int) error {
	if b.err == nil && n > b.limit-b.Len() {
		b.err = &EncodingLimitError{Limit: b.limit}
	}
	return b.err
}
func (b *boundedEncoding) Write(p []byte) (int, error) {
	if err := b.allow(len(p)); err != nil {
		return 0, err
	}
	return b.Buffer.Write(p)
}
func (b *boundedEncoding) WriteString(p string) (int, error) {
	if err := b.allow(len(p)); err != nil {
		return 0, err
	}
	return b.Buffer.WriteString(p)
}
func (b *boundedEncoding) WriteByte(p byte) error {
	if err := b.allow(1); err != nil {
		return err
	}
	return b.Buffer.WriteByte(p)
}
func encodingError(out encodingWriter) error {
	if b, ok := out.(*boundedEncoding); ok {
		return b.err
	}
	return nil
}

func appendValue(out encodingWriter, value any) error {
	if err := encodingError(out); err != nil {
		return err
	}
	switch value := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if value {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		appendString(out, value)
	case json.Number:
		number, err := canonicalNumber(value.String())
		if err != nil {
			return err
		}
		out.WriteString(number)
	case int:
		out.WriteString(strconv.Itoa(value))
	case int8:
		out.WriteString(strconv.FormatInt(int64(value), 10))
	case int16:
		out.WriteString(strconv.FormatInt(int64(value), 10))
	case int32:
		out.WriteString(strconv.FormatInt(int64(value), 10))
	case int64:
		out.WriteString(strconv.FormatInt(value, 10))
	case uint:
		out.WriteString(strconv.FormatUint(uint64(value), 10))
	case uint8:
		out.WriteString(strconv.FormatUint(uint64(value), 10))
	case uint16:
		out.WriteString(strconv.FormatUint(uint64(value), 10))
	case uint32:
		out.WriteString(strconv.FormatUint(uint64(value), 10))
	case uint64:
		out.WriteString(strconv.FormatUint(value, 10))
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				out.WriteByte(',')
			}
			appendString(out, key)
			out.WriteByte(':')
			if err := appendValue(out, value[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for index, item := range value {
			if index > 0 {
				out.WriteByte(',')
			}
			if err := appendValue(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case []string:
		out.WriteByte('[')
		for index, item := range value {
			if index > 0 {
				out.WriteByte(',')
			}
			appendString(out, item)
		}
		out.WriteByte(']')
	case json.RawMessage:
		if bounded, ok := out.(*boundedEncoding); ok && len(value) > bounded.limit {
			return &EncodingLimitError{Limit: bounded.limit}
		}
		decoder := json.NewDecoder(bytes.NewReader(value))
		decoder.UseNumber()
		var decoded any
		if err := decoder.Decode(&decoded); err != nil || singleValue(decoder) != nil {
			return fmt.Errorf("raw JSON is malformed")
		}
		return appendValue(out, decoded)
	case float32, float64:
		return fmt.Errorf("floating-point values are unsupported; decode JSON with UseNumber")
	default:
		return fmt.Errorf("unsupported JSON value type %T", value)
	}
	return encodingError(out)
}

func canonicalNumber(raw string) (string, error) {
	if raw == "" || len(raw) > 4096 {
		return "", fmt.Errorf("invalid JSON number")
	}
	index := 0
	negative := false
	if raw[index] == '-' {
		negative = true
		index++
		if index == len(raw) {
			return "", fmt.Errorf("invalid JSON number")
		}
	}
	integerStart := index
	if raw[index] == '0' {
		index++
		if index < len(raw) && raw[index] >= '0' && raw[index] <= '9' {
			return "", fmt.Errorf("invalid JSON number")
		}
	} else if raw[index] >= '1' && raw[index] <= '9' {
		for index < len(raw) && raw[index] >= '0' && raw[index] <= '9' {
			index++
		}
	} else {
		return "", fmt.Errorf("invalid JSON number")
	}
	digits := raw[integerStart:index]
	fractionLength := 0
	if index < len(raw) && raw[index] == '.' {
		index++
		fractionStart := index
		for index < len(raw) && raw[index] >= '0' && raw[index] <= '9' {
			index++
		}
		if fractionStart == index {
			return "", fmt.Errorf("invalid JSON number")
		}
		digits += raw[fractionStart:index]
		fractionLength = index - fractionStart
	}
	exponent := 0
	if index < len(raw) && (raw[index] == 'e' || raw[index] == 'E') {
		index++
		sign := 1
		if index < len(raw) && (raw[index] == '+' || raw[index] == '-') {
			if raw[index] == '-' {
				sign = -1
			}
			index++
		}
		exponentStart := index
		for index < len(raw) && raw[index] >= '0' && raw[index] <= '9' {
			index++
		}
		if exponentStart == index {
			return "", fmt.Errorf("invalid JSON number")
		}
		parsed, err := strconv.Atoi(raw[exponentStart:index])
		if err != nil || parsed > 4096 {
			return "", fmt.Errorf("JSON number exponent is unsupported")
		}
		exponent = sign * parsed
	}
	if index != len(raw) {
		return "", fmt.Errorf("invalid JSON number")
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return "0", nil
	}
	scale := exponent - fractionLength
	for strings.HasSuffix(digits, "0") {
		digits = strings.TrimSuffix(digits, "0")
		scale++
	}
	if len(digits)+absolute(scale)+4 > 4096 {
		return "", fmt.Errorf("JSON number is too large")
	}
	value := ""
	if scale >= 0 {
		value = digits + strings.Repeat("0", scale)
	} else if point := len(digits) + scale; point > 0 {
		value = digits[:point] + "." + digits[point:]
	} else {
		value = "0." + strings.Repeat("0", -point) + digits
	}
	if negative {
		value = "-" + value
	}
	return value, nil
}

func singleValue(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return fmt.Errorf("multiple JSON values")
	}
	return err
}

func appendString(out encodingWriter, value string) {
	encoded, _ := json.Marshal(value)
	out.Write(encoded)
}

func absolute(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
