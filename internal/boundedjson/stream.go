// Package boundedjson selects JSON using a fixed-size input buffer. Skipped
// values are validated without materializing scalar tokens or containers.
package boundedjson

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

type LimitError struct {
	Limit, Observed int
	Depth           bool
}

func (e *LimitError) Error() string {
	return fmt.Sprintf("bounded JSON limit %d exceeded (at least %d)", e.Limit, e.Observed)
}

type Stream struct {
	reader   *bufio.Reader
	maxDepth int
}

func New(reader io.Reader, maxDepth int) *Stream {
	return &Stream{reader: bufio.NewReaderSize(reader, 4096), maxDepth: maxDepth}
}
func (s *Stream) Peek() (byte, error) {
	for {
		b, err := s.reader.Peek(1)
		if err != nil {
			return 0, err
		}
		switch b[0] {
		case ' ', '\t', '\r', '\n':
			s.reader.ReadByte()
		default:
			return b[0], nil
		}
	}
}
func (s *Stream) Take(want byte) error {
	b, err := s.Peek()
	if err != nil {
		return err
	}
	if b != want {
		return fmt.Errorf("expected JSON delimiter %q", want)
	}
	_, err = s.reader.ReadByte()
	return err
}
func (s *Stream) End() error {
	_, err := s.Peek()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("trailing JSON")
}

type capture struct {
	data                      []byte
	limit                     int
	discardOverflow, overflow bool
}

func (c *capture) add(b byte) error {
	if c == nil {
		return nil
	}
	if len(c.data) >= c.limit {
		c.overflow = true
		if c.discardOverflow {
			return nil
		}
		return &LimitError{Limit: c.limit, Observed: c.limit + 1}
	}
	c.data = append(c.data, b)
	return nil
}
func (s *Stream) byte(c *capture) (byte, error) {
	b, err := s.reader.ReadByte()
	if err != nil {
		return 0, err
	}
	return b, c.add(b)
}
func (s *Stream) punctuation(c *capture, b byte) error {
	if err := s.Take(b); err != nil {
		return err
	}
	return c.add(b)
}
func (s *Stream) string(c *capture) error {
	if err := s.punctuation(c, '"'); err != nil {
		return err
	}
	for {
		b, err := s.reader.ReadByte()
		if err != nil {
			return err
		}
		if b >= utf8.RuneSelf {
			if err := s.reader.UnreadByte(); err != nil {
				return err
			}
			r, n, err := s.reader.ReadRune()
			if err != nil {
				return err
			}
			if r == utf8.RuneError && n == 1 {
				return fmt.Errorf("invalid JSON UTF-8")
			}
			var encoded [utf8.UTFMax]byte
			count := utf8.EncodeRune(encoded[:], r)
			for _, b := range encoded[:count] {
				if err := c.add(b); err != nil {
					return err
				}
			}
			continue
		}
		if err := c.add(b); err != nil {
			return err
		}
		if b == '"' {
			return nil
		}
		if b < 0x20 {
			return fmt.Errorf("unescaped JSON control character")
		}
		if b == '\\' {
			escape, err := s.byte(c)
			if err != nil {
				return err
			}
			switch escape {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				for i := 0; i < 4; i++ {
					h, err := s.byte(c)
					if err != nil {
						return err
					}
					if !(h >= '0' && h <= '9' || h >= 'a' && h <= 'f' || h >= 'A' && h <= 'F') {
						return fmt.Errorf("invalid JSON unicode escape")
					}
				}
			default:
				return fmt.Errorf("invalid JSON escape")
			}
		}
	}
}
func (s *Stream) number(c *capture) error {
	peek := func() byte {
		b, err := s.reader.Peek(1)
		if err != nil {
			return 0
		}
		return b[0]
	}
	consume := func() error { _, err := s.byte(c); return err }
	if peek() == '-' {
		if err := consume(); err != nil {
			return err
		}
	}
	if peek() == '0' {
		if err := consume(); err != nil {
			return err
		}
	} else {
		if peek() < '1' || peek() > '9' {
			return fmt.Errorf("invalid JSON number")
		}
		for peek() >= '0' && peek() <= '9' {
			if err := consume(); err != nil {
				return err
			}
		}
	}
	if peek() == '.' {
		if err := consume(); err != nil {
			return err
		}
		if peek() < '0' || peek() > '9' {
			return fmt.Errorf("invalid JSON fraction")
		}
		for peek() >= '0' && peek() <= '9' {
			if err := consume(); err != nil {
				return err
			}
		}
	}
	if peek() == 'e' || peek() == 'E' {
		if err := consume(); err != nil {
			return err
		}
		if peek() == '+' || peek() == '-' {
			if err := consume(); err != nil {
				return err
			}
		}
		if peek() < '0' || peek() > '9' {
			return fmt.Errorf("invalid JSON exponent")
		}
		for peek() >= '0' && peek() <= '9' {
			if err := consume(); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Stream) value(c *capture, depth int) error {
	if depth > s.maxDepth {
		return &LimitError{Limit: s.maxDepth, Observed: depth, Depth: true}
	}
	b, err := s.Peek()
	if err != nil {
		return err
	}
	switch b {
	case '"':
		return s.string(c)
	case '{', '[':
		end := byte(']')
		if b == '{' {
			end = '}'
		}
		if err := s.punctuation(c, b); err != nil {
			return err
		}
		first := true
		for {
			next, err := s.Peek()
			if err != nil {
				return err
			}
			if next == end {
				return s.punctuation(c, end)
			}
			if !first {
				if err := s.punctuation(c, ','); err != nil {
					return err
				}
			}
			first = false
			if b == '{' {
				if err := s.string(c); err != nil {
					return err
				}
				if err := s.punctuation(c, ':'); err != nil {
					return err
				}
			}
			if err := s.value(c, depth+1); err != nil {
				return err
			}
		}
	case 't', 'f', 'n':
		literal := "null"
		if b == 't' {
			literal = "true"
		}
		if b == 'f' {
			literal = "false"
		}
		for i := range literal {
			actual, err := s.byte(c)
			if err != nil {
				return err
			}
			if actual != literal[i] {
				return fmt.Errorf("invalid JSON literal")
			}
		}
		return nil
	default:
		return s.number(c)
	}
}
func (s *Stream) Skip() error { return s.value(nil, 1) }
func (s *Stream) ReadValue(limit int) (json.RawMessage, error) {
	if limit < 1 {
		return nil, fmt.Errorf("invalid JSON byte budget")
	}
	c := &capture{limit: limit}
	err := s.value(c, 1)
	return c.data, err
}
func (s *Stream) Key(limit int) (string, bool, error) {
	c := &capture{limit: limit, discardOverflow: true}
	if err := s.string(c); err != nil {
		return "", false, err
	}
	if c.overflow {
		return "", false, nil
	}
	var key string
	err := json.Unmarshal(c.data, &key)
	return key, true, err
}

func (s *Stream) Array(limit int, visit func(int, json.RawMessage) error) (int, error) {
	if err := s.Take('['); err != nil {
		return 0, err
	}
	count := 0
	for {
		b, err := s.Peek()
		if err != nil {
			return count, err
		}
		if b == ']' {
			return count, s.Take(']')
		}
		if count > 0 {
			if err := s.Take(','); err != nil {
				return count, err
			}
		}
		raw, err := s.ReadValue(limit)
		if err != nil {
			return count, err
		}
		if err := visit(count, raw); err != nil {
			return count, err
		}
		count++
	}
}

// Select preserves object/array mapping selectors. Each selected subtree and the
// combined mapped array share the same fixed serialized budget.
func (s *Stream) Select(path []string, limit int) (json.RawMessage, bool, error) {
	return s.selectPath(path, limit, false, 1)
}
func (s *Stream) selectPath(path []string, limit int, mapping bool, depth int) (json.RawMessage, bool, error) {
	if depth > s.maxDepth {
		return nil, true, &LimitError{Limit: s.maxDepth, Observed: depth, Depth: true}
	}
	if len(path) == 0 {
		raw, err := s.ReadValue(limit)
		return raw, true, err
	}
	b, err := s.Peek()
	if err != nil {
		return nil, true, err
	}
	if b == '[' && !strings.HasSuffix(path[0], "[]") {
		if err := s.Take('['); err != nil {
			return nil, true, err
		}
		out := &capture{limit: limit}
		out.add('[')
		count := 0
		first := true
		for {
			b, err := s.Peek()
			if err != nil {
				return nil, true, err
			}
			if b == ']' {
				if err := s.Take(']'); err != nil {
					return nil, true, err
				}
				if err := out.add(']'); err != nil {
					return nil, true, err
				}
				return out.data, true, nil
			}
			if !first {
				if err := s.Take(','); err != nil {
					return nil, true, err
				}
			}
			first = false
			item, found, err := s.selectPath(path, limit, true, depth+1)
			if err != nil {
				return nil, found, err
			}
			if found {
				if count > 0 {
					if err := out.add(','); err != nil {
						return nil, true, err
					}
				}
				for _, v := range item {
					if err := out.add(v); err != nil {
						return nil, true, err
					}
				}
				count++
			}
		}
	}
	if b != '{' {
		if !mapping {
			return nil, true, fmt.Errorf("binding continuation through null or scalar")
		}
		if b == '"' {
			if err := s.Take('"'); err != nil {
				return nil, false, err
			}
			decoded := &stringReader{source: s.reader}
			nested := New(decoded, s.maxDepth)
			value, found, err := nested.selectPath(path, limit, true, depth+1)
			if err != nil {
				var bound *LimitError
				if errors.As(err, &bound) {
					return nil, true, err
				}
				if _, drainErr := io.Copy(io.Discard, decoded); drainErr != nil {
					return nil, false, drainErr
				}
				return nil, false, nil
			}
			if nested.End() != nil {
				if _, drainErr := io.Copy(io.Discard, decoded); drainErr != nil {
					return nil, false, drainErr
				}
				return nil, false, nil
			}
			if decoded.err != nil {
				return nil, false, decoded.err
			}
			return value, found, nil
		}
		return nil, false, s.Skip()
	}
	if err := s.Take('{'); err != nil {
		return nil, true, err
	}
	found := false
	var selected json.RawMessage
	first := true
	name := strings.TrimSuffix(path[0], "[]")
	for {
		b, err := s.Peek()
		if err != nil {
			return nil, true, err
		}
		if b == '}' {
			if err := s.Take('}'); err != nil {
				return nil, true, err
			}
			break
		}
		if !first {
			if err := s.Take(','); err != nil {
				return nil, true, err
			}
		}
		first = false
		key, complete, err := s.Key(limit)
		if err != nil {
			return nil, true, err
		}
		if err := s.Take(':'); err != nil {
			return nil, true, err
		}
		if !complete || key != name {
			if err := s.Skip(); err != nil {
				return nil, true, err
			}
			continue
		}
		if found {
			return nil, true, fmt.Errorf("duplicate selected JSON key")
		}
		found = true
		if strings.HasSuffix(path[0], "[]") {
			b, err := s.Peek()
			if err != nil || b != '[' {
				return nil, true, fmt.Errorf("binding field is not an array")
			}
		}
		selected, _, err = s.selectPath(path[1:], limit, false, depth+1)
		if err != nil {
			return nil, true, err
		}
	}
	if !found && !mapping {
		return nil, true, fmt.Errorf("binding field is missing")
	}
	return bytes.Clone(selected), found, nil
}
