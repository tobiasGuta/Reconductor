package command

import (
	"encoding/json"
	"strings"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

// Every nonempty output line occupies at least one semantic value node. Stop
// splitting before accumulating more entries than the existing node contract.
func boundedLines(raw string) ([]string, bool) {
	var lines []string
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(lines) == domain.InlineSemanticJSONMaxNodes {
			return nil, true
		}
		lines = append(lines, line)
	}
	return lines, false
}

// Marshal collections item by item. Each item comes from an already byte-
// bounded input; duplicates and JSON escaping cannot grow the final accumulator
// beyond the remaining evidence authority. HTTP's empty source array is emitted
// directly, avoiding a second whole-result decode/remarshal.
func marshalProviderOutput(p ProviderOutput, http bool, limit int64) ([]byte, error) {
	c := &outputCapture{remaining: limit, limit: limit, cancel: func() {}}
	if limit < 1 {
		return nil, &capability.OutputLimitError{Limit: limit}
	}
	w := &captureStream{capture: c}
	write := func(raw string) error { _, err := w.Write([]byte(raw)); return err }
	if err := write("{"); err != nil {
		return nil, err
	}
	first := true
	field := func(name string, value any) error {
		if !first {
			if err := write(","); err != nil {
				return err
			}
		}
		first = false
		if err := write(`"` + name + `":`); err != nil {
			return err
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		_, err = w.Write(raw)
		return err
	}
	// Keep each array bounded while encoding, rather than json.Marshal of the
	// complete duplicated normalized value.
	array := func(name string, n int, at func(int) any) error {
		if !first {
			if err := write(","); err != nil {
				return err
			}
		}
		first = false
		if err := write(`"` + name + `":[`); err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			if i > 0 {
				if err := write(","); err != nil {
					return err
				}
			}
			raw, err := json.Marshal(at(i))
			if err != nil {
				return err
			}
			if _, err = w.Write(raw); err != nil {
				return err
			}
		}
		return write("]")
	}
	for _, a := range []struct {
		name string
		n    int
		at   func(int) any
	}{
		{"lines", len(p.Lines), func(i int) any { return p.Lines[i] }},
		{"authorized", len(p.Authorized), func(i int) any { return p.Authorized[i] }},
		{"authorized_urls", len(p.AuthorizedURLs), func(i int) any { return p.AuthorizedURLs[i] }},
		{"authorized_records", len(p.AuthorizedRecords), func(i int) any { return p.AuthorizedRecords[i] }},
		{"filtered", len(p.Filtered), func(i int) any { return p.Filtered[i] }},
		{"records", len(p.Records), func(i int) any { return p.Records[i] }},
		{"warnings", len(p.Warnings), func(i int) any { return p.Warnings[i] }},
	} {
		if err := array(a.name, a.n, a.at); err != nil {
			return nil, err
		}
	}
	if http {
		if err := array("authorized_source_records", len(p.AuthorizedSourceRecords), func(i int) any { return p.AuthorizedSourceRecords[i] }); err != nil {
			return nil, err
		}
	}
	if err := field("accepted_count", p.AcceptedCount); err != nil {
		return nil, err
	}
	if err := field("filtered_count", p.FilteredCount); err != nil {
		return nil, err
	}
	if err := write("}"); err != nil {
		return nil, err
	}
	return w.data, nil
}
