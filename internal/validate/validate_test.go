package validate

import (
	"strings"
	"testing"
)

func TestValidators(t *testing.T) {
	cases := []struct {
		name  string
		data  string
		valid bool
	}{
		{"none", "anything at all", true},
		{"none", "", true},
		{"yaml", "a: 1\nb: [1,2,3]\n", true},
		{"yaml", "---\na: 1\n---\nb: 2\n", true}, // multi-document stream
		{"yaml", "", true},                       // empty is a valid (null) document
		{"yaml", "foo: [bar", false},
		{"json", `{"a":1}`, true},
		{"json", `{"a":[1,2,3]}`, true},
		{"json", "{}\n", true}, // one value + trailing whitespace
		{"json", `{"a":}`, false},
		{"json", "", false},      // empty is not valid JSON
		{"json", "{} {}", false}, // multiple top-level values
		{"json", "1 2", false},
		{"json", "{}garbage", false},
		{"jsonl", "{\"a\":1}\n{\"b\":2}\n", true},
		{"jsonl", `{"a":1}`, true},                // single line, no trailing newline
		{"jsonl", "{\"a\":1}\n\n{\"b\":2}", true}, // blank line between records
		{"jsonl", "", false},                      // no records
		{"jsonl", "   \n", false},                 // only blank lines
		{"jsonl", "{} {}\n", false},               // two values on one line
		{"jsonl", "{\n\"a\":1\n}\n", false},       // a single object split across lines
		{"jsonl", "{\n", false},                   // malformed line
	}
	for _, c := range cases {
		err := Validate(c.name, strings.NewReader(c.data))
		if c.valid && err != nil {
			t.Errorf("%s %q: unexpected error: %v", c.name, c.data, err)
		}
		if !c.valid && err == nil {
			t.Errorf("%s %q: expected error, got nil", c.name, c.data)
		}
	}
	if err := Validate("nope", strings.NewReader("x")); err == nil {
		t.Errorf("unknown validator should error")
	}
	if !Known("yaml") || !Known("jsonl") || Known("nope") {
		t.Errorf("Known returned wrong result")
	}
}
