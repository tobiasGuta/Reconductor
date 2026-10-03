package strictjsonschema

import (
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
)

func strictValue(t *testing.T, raw string) any {
	t.Helper()
	value, _, _, _, err := canonicaljson.ParseStrict([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestValidateClosedSchemaKeywordsUsedByCapabilityOutputs(t *testing.T) {
	schema := strictValue(t, `{
		"type":"object",
		"additionalProperties":false,
		"required":["id","items","when","count"],
		"properties":{
			"id":{"type":"string","format":"uuid"},
			"items":{"type":"array","minItems":1,"maxItems":2,"uniqueItems":true,"items":{"$ref":"#/$defs/item"}},
			"when":{"type":"string","format":"date-time"},
			"count":{"type":"integer","minimum":1,"maximum":3}
		},
		"$defs":{"item":{"type":"string","minLength":1,"maxLength":8,"pattern":"^[a-z]+$"}}
	}`)
	valid := strictValue(t, `{"id":"123e4567-e89b-42d3-a456-426614174000","items":["one","two"],"when":"2026-09-14T12:00:00Z","count":2}`)
	if err := Validate(schema, valid); err != nil {
		t.Fatalf("valid output rejected: %v", err)
	}
	for name, raw := range map[string]string{
		"unknown property": `{"id":"123e4567-e89b-42d3-a456-426614174000","items":["one"],"when":"2026-09-14T12:00:00Z","count":2,"extra":true}`,
		"duplicate item":   `{"id":"123e4567-e89b-42d3-a456-426614174000","items":["one","one"],"when":"2026-09-14T12:00:00Z","count":2}`,
		"noninteger":       `{"id":"123e4567-e89b-42d3-a456-426614174000","items":["one"],"when":"2026-09-14T12:00:00Z","count":2.5}`,
		"invalid time":     `{"id":"123e4567-e89b-42d3-a456-426614174000","items":["one"],"when":"yesterday","count":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := Validate(schema, strictValue(t, raw)); err == nil {
				t.Fatal("invalid output accepted")
			}
		})
	}
}

func TestValidateOneOfRequiresExactlyOneBranch(t *testing.T) {
	schema := strictValue(t, `{"oneOf":[{"type":"number"},{"type":"integer"}]}`)
	if err := Validate(schema, strictValue(t, `1`)); err == nil {
		t.Fatal("value matching both oneOf branches was accepted")
	}
	if err := Validate(schema, strictValue(t, `1.5`)); err != nil {
		t.Fatalf("value matching one branch rejected: %v", err)
	}
}
