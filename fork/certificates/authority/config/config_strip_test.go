package config

import (
	"encoding/json"
	"testing"
)

func TestStripJSONComments(t *testing.T) {
	in := `{
# top-level comment
"address": ":443", # trailing comment
"weird": "hash # inside string stays",
"esc": "quote \" then # still string",
"n": 1
}`
	out := StripJSONComments([]byte(in))
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("stripped JSON invalid: %v\n%s", err, out)
	}
	if m["weird"] != "hash # inside string stays" {
		t.Errorf("string with # mangled: %q", m["weird"])
	}
	if m["esc"] != "quote \" then # still string" {
		t.Errorf("escaped-quote string mangled: %q", m["esc"])
	}
	if m["address"] != ":443" {
		t.Errorf("trailing-comment field wrong: %q", m["address"])
	}
}
