// Package validate holds the built-in content validators selectable by name from
// a bucket's `validator` config field. Validation runs server-side on push, before
// the data is committed to the store.
//
// Validators read from an io.Reader (the streamed temp file) rather than a full
// in-memory buffer. JSON is validated token-by-token with bounded memory; YAML is
// decoded one document at a time (yaml.v3 still builds a per-document parse tree).
package validate

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// Func validates a pushed payload streamed from r, returning a non-nil error to
// reject it.
type Func func(r io.Reader) error

var registry = map[string]Func{
	"none": func(io.Reader) error { return nil },
	"json": func(r io.Reader) error {
		dec := json.NewDecoder(r)
		var v any
		if err := dec.Decode(&v); err != nil {
			return fmt.Errorf("invalid json: %w", err) // includes EOF for empty input
		}
		// A JSON document holds exactly one top-level value: nothing but trailing
		// whitespace may follow.
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			return fmt.Errorf("invalid json: unexpected data after top-level value")
		}
		return nil
	},
	"jsonl": func(r io.Reader) error {
		br := bufio.NewReader(r)
		lineNo, records := 0, 0
		for {
			line, err := br.ReadString('\n')
			lineNo++
			if trimmed := strings.TrimSpace(line); trimmed != "" {
				if !json.Valid([]byte(trimmed)) {
					return fmt.Errorf("invalid jsonl: line %d is not a single valid json value", lineNo)
				}
				records++
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return fmt.Errorf("invalid jsonl: %w", err)
			}
		}
		if records == 0 {
			return fmt.Errorf("invalid jsonl: no json records")
		}
		return nil
	},
	"yaml": func(r io.Reader) error {
		dec := yaml.NewDecoder(r)
		for {
			var v any
			err := dec.Decode(&v)
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("invalid yaml: %w", err)
			}
			// v is discarded each iteration so memory stays bounded by one document.
		}
	},
}

// Known reports whether name refers to a registered validator.
func Known(name string) bool {
	_, ok := registry[name]
	return ok
}

// Names returns the registered validator names (for error messages).
func Names() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	return out
}

// Validate runs the named validator against r. An empty or unknown name is an error;
// callers should validate config up front so this never trips at runtime.
func Validate(name string, r io.Reader) error {
	fn, ok := registry[name]
	if !ok {
		return fmt.Errorf("unknown validator %q", name)
	}
	return fn(r)
}
