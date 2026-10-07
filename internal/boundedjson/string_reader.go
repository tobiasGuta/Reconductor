package boundedjson

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

// stringReader incrementally decodes one JSON string after its opening quote.
// Its decoded payload can itself be JSON. Only a single rune/escape is buffered,
// so selecting a small nested field does not materialize unrelated string data.
type stringReader struct {
	source  *bufio.Reader
	pending []byte
	done    bool
	err     error
}

func (r *stringReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	n := 0
	for n < len(dst) {
		if len(r.pending) > 0 {
			k := copy(dst[n:], r.pending)
			n += k
			r.pending = r.pending[k:]
			continue
		}
		if r.err != nil {
			return n, r.err
		}
		if r.done {
			return n, io.EOF
		}
		b, err := r.source.ReadByte()
		if err != nil {
			r.err = io.ErrUnexpectedEOF
			continue
		}
		if b == '"' {
			r.done = true
			continue
		}
		if b < 0x20 {
			r.err = fmt.Errorf("unescaped JSON string control")
			continue
		}
		if b >= utf8.RuneSelf {
			r.source.UnreadByte()
			v, size, err := r.source.ReadRune()
			if err != nil || (v == utf8.RuneError && size == 1) {
				r.err = fmt.Errorf("invalid JSON UTF-8")
				continue
			}
			r.pending = utf8.AppendRune(r.pending[:0], v)
			continue
		}
		if b != '\\' {
			dst[n] = b
			n++
			continue
		}
		escape, err := r.source.ReadByte()
		if err != nil {
			r.err = io.ErrUnexpectedEOF
			continue
		}
		// Delegate the fixed-size escape to the same JSON Unicode semantics as
		// ordinary decoding, including surrogate pairs and replacement runes.
		var encoded [14]byte
		encoded[0], encoded[1], encoded[2] = '"', '\\', escape
		size := 3
		if escape == 'u' {
			if _, err = io.ReadFull(r.source, encoded[3:7]); err != nil {
				r.err = err
				continue
			}
			size = 7
			// A following Unicode escape may complete a surrogate pair. Decoding
			// two ordinary escapes together is also equivalent and remains fixed.
			if next, _ := r.source.Peek(6); len(next) == 6 && next[0] == '\\' && next[1] == 'u' {
				copy(encoded[7:13], next)
				r.source.Discard(6)
				size = 13
			}
		}
		encoded[size] = '"'
		var decoded string
		if err = json.Unmarshal(encoded[:size+1], &decoded); err != nil {
			r.err = err
			continue
		}
		r.pending = append(r.pending[:0], decoded...)
	}
	return n, nil
}
