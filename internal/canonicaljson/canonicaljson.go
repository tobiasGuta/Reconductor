package canonicaljson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

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

func appendValue(out *bytes.Buffer, value any) error {
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
	return nil
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

func appendString(out *bytes.Buffer, value string) {
	encoded, _ := json.Marshal(value)
	out.Write(encoded)
}

func absolute(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
