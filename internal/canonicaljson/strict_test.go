package canonicaljson

import (
	"bytes"
	"testing"
)

func TestParseStrictFrozenCanonicalVectors(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{"whitespace", []byte(" { \"b\" : 2, \"a\" : 1 } \n"), `{"a":1,"b":2}`},
		{"reordered keys", []byte(`{"a":1,"b":2}`), `{"a":1,"b":2}`},
		{"integer", []byte(`1`), `1`},
		{"decimal", []byte(`1.0`), `1`},
		{"exponent", []byte(`1e0`), `1`},
		{"escaped unicode", []byte(`"\u00e9"`), `"é"`},
		{"literal unicode", []byte(`"é"`), `"é"`},
		{"trailing whitespace", []byte("true\r\n\t"), `true`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, canonical, _, _, err := ParseStrict(test.raw)
			if err != nil || string(canonical) != test.want {
				t.Fatalf("canonical=%q error=%v want=%q", canonical, err, test.want)
			}
		})
	}
}

func TestParseStrictRejectsFrozenInvalidVectors(t *testing.T) {
	for name, raw := range map[string][]byte{
		"duplicate":        []byte(`{"a":1,"a":2}`),
		"nested duplicate": []byte(`{"a":{"b":1,"b":2}}`),
		"multiple values":  []byte(`{} []`),
		"trailing data":    []byte(`{}x`),
		"invalid utf8":     append([]byte(`"`), 0xff, '"'),
		"huge exponent":    []byte(`1e99999`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, _, err := ParseStrict(raw); err == nil {
				t.Fatalf("accepted %q", raw)
			}
		})
	}
}

func TestParseStrictFrozenNodeAndDepthAccounting(t *testing.T) {
	_, canonical, nodes, depth, err := ParseStrict([]byte(`{"a":[],"b":{},"c":[null,true,"x",1]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, []byte(`{"a":[],"b":{},"c":[null,true,"x",1]}`)) || nodes != 8 || depth != 3 {
		t.Fatalf("canonical=%s nodes=%d depth=%d", canonical, nodes, depth)
	}
}
