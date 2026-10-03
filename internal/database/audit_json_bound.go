package database

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"strconv"
	"strings"
)

// auditJSONBTextSize mirrors PostgreSQL's UTF-8 jsonb::text representation:
// comma/colon spaces, JSON escaping (not HTML escaping), and numeric exponent
// expansion. Only already-bounded projector entries reach this function.
// Sizes above the ceiling saturate at ceiling+1; no huge decimal is built.
func auditJSONBTextSize(raw []byte) (int, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return 0, err
	}
	const overflow = domain.DiagnosticMaxBytes + 1
	add := func(a, b int) int {
		if a > overflow-b {
			return overflow
		}
		return a + b
	}
	stringSize := func(value string) (int, error) {
		n := 2
		for i := 0; i < len(value); i++ {
			b := value[i]
			if b == 0 {
				return 0, fmt.Errorf("audit JSONB cannot contain U+0000")
			}
			extra := 1
			switch b {
			case '"', '\\', '\b', '\f', '\n', '\r', '\t':
				extra = 2
			default:
				if b < 0x20 {
					extra = 6
				}
			}
			n = add(n, extra)
		}
		return n, nil
	}
	var size func(any) (int, error)
	size = func(value any) (int, error) {
		switch v := value.(type) {
		case nil:
			return 4, nil
		case bool:
			if v {
				return 4, nil
			}
			return 5, nil
		case string:
			return stringSize(v)
		case json.Number:
			text := string(v)
			negative := strings.HasPrefix(text, "-")
			text = strings.TrimPrefix(text, "-")
			exponent := int64(0)
			if index := strings.IndexAny(text, "eE"); index >= 0 {
				parsed, err := strconv.ParseInt(text[index+1:], 10, 32)
				if err != nil || parsed > overflow || parsed < -overflow {
					return overflow, nil
				}
				exponent = parsed
				text = text[:index]
			}
			fraction := 0
			if index := strings.IndexByte(text, '.'); index >= 0 {
				fraction = len(text) - index - 1
				text = text[:index] + text[index+1:]
			}
			digits := strings.TrimLeft(text, "0")
			if digits == "" {
				digits = "0"
				negative = false
			}
			scale := int64(fraction) - exponent
			n := int64(len(digits))
			if scale < 0 {
				if digits != "0" {
					n -= scale
				}
			} else if scale > 0 {
				if n > scale {
					n++
				} else {
					n = scale + 2
				}
			}
			if negative {
				n++
			}
			if n > overflow {
				return overflow, nil
			}
			return int(n), nil
		case []any:
			n := 2
			for i, item := range v {
				if i > 0 {
					n = add(n, 2)
				}
				child, err := size(item)
				if err != nil {
					return 0, err
				}
				n = add(n, child)
			}
			return n, nil
		case map[string]any:
			n := 2
			i := 0
			for key, item := range v {
				if i > 0 {
					n = add(n, 2)
				}
				i++
				keySize, err := stringSize(key)
				if err != nil {
					return 0, err
				}
				child, err := size(item)
				if err != nil {
					return 0, err
				}
				n = add(add(add(n, keySize), 2), child)
			}
			return n, nil
		default:
			return 0, fmt.Errorf("invalid audit JSON value")
		}
	}
	return size(value)
}

func checkAuditProjection(raw []byte) error {
	size, err := auditJSONBTextSize(raw)
	if err != nil {
		return err
	}
	if size > domain.DiagnosticMaxBytes {
		return &ProjectionContractLimitError{Limit: domain.ResultContractLimitV1{Subject: domain.LimitProjectionItem, Unit: domain.LimitBytes, Limit: domain.DiagnosticMaxBytes, Observed: uint64(size)}}
	}
	return nil
}
