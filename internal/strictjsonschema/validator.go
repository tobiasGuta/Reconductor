package strictjsonschema

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func Validate(schema, value any) error { return validate(schema, value, schema, 0) }

func validate(schema, value, root any, depth int) error {
	if depth > 256 {
		return fmt.Errorf("schema reference depth exceeded")
	}
	if allowed, ok := schema.(bool); ok {
		if !allowed {
			return fmt.Errorf("value is rejected by false schema")
		}
		return nil
	}
	object, ok := schema.(map[string]any)
	if !ok {
		return fmt.Errorf("schema must be an object or boolean")
	}
	if rawRef, ok := object["$ref"].(string); ok && strings.HasPrefix(rawRef, "#/") {
		resolved, err := resolvePointer(root, rawRef[2:])
		if err != nil {
			return err
		}
		if err := validate(resolved, value, root, depth+1); err != nil {
			return err
		}
	}
	if rawConst, ok := object["const"]; ok && !equalJSON(rawConst, value) {
		return fmt.Errorf("value does not equal const")
	}
	if rawEnum, ok := object["enum"].([]any); ok {
		matched := false
		for _, candidate := range rawEnum {
			if equalJSON(candidate, value) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("value is outside enum")
		}
	}
	if rawTypes, ok := object["type"]; ok {
		if !matchesTypes(rawTypes, value) {
			return fmt.Errorf("value has wrong JSON type")
		}
	}
	for _, keyword := range []string{"allOf", "anyOf", "oneOf"} {
		schemas, ok := object[keyword].([]any)
		if !ok {
			continue
		}
		matches := 0
		for _, candidate := range schemas {
			if validate(candidate, value, root, depth+1) == nil {
				matches++
			}
		}
		switch keyword {
		case "allOf":
			if matches != len(schemas) {
				return fmt.Errorf("value does not satisfy allOf")
			}
		case "anyOf":
			if matches == 0 {
				return fmt.Errorf("value does not satisfy anyOf")
			}
		case "oneOf":
			if matches != 1 {
				return fmt.Errorf("value does not satisfy exactly one oneOf branch")
			}
		}
	}
	switch typed := value.(type) {
	case map[string]any:
		return validateObject(object, typed, root, depth)
	case []any:
		return validateArray(object, typed, root, depth)
	case string:
		return validateString(object, typed)
	case json.Number:
		return validateNumber(object, typed)
	}
	return nil
}

func validateObject(schema map[string]any, value map[string]any, root any, depth int) error {
	required := map[string]bool{}
	if items, ok := schema["required"].([]any); ok {
		for _, item := range items {
			name, ok := item.(string)
			if !ok {
				return fmt.Errorf("schema required member is invalid")
			}
			required[name] = true
		}
	}
	for name := range required {
		if _, ok := value[name]; !ok {
			return fmt.Errorf("required property %q is missing", name)
		}
	}
	properties, _ := schema["properties"].(map[string]any)
	for name, item := range value {
		propertySchema, known := properties[name]
		if known {
			if err := validate(propertySchema, item, root, depth+1); err != nil {
				return fmt.Errorf("property %s: %w", name, err)
			}
			continue
		}
		switch additional := schema["additionalProperties"].(type) {
		case bool:
			if !additional {
				return fmt.Errorf("unknown property %q", name)
			}
		case map[string]any:
			if err := validate(additional, item, root, depth+1); err != nil {
				return fmt.Errorf("additional property %s: %w", name, err)
			}
		}
	}
	return nil
}
func validateArray(schema map[string]any, value []any, root any, depth int) error {
	if minimum, ok := schemaInteger(schema["minItems"]); ok && len(value) < minimum {
		return fmt.Errorf("array has too few items")
	}
	if maximum, ok := schemaInteger(schema["maxItems"]); ok && len(value) > maximum {
		return fmt.Errorf("array has too many items")
	}
	if itemSchema, ok := schema["items"]; ok {
		for index, item := range value {
			if err := validate(itemSchema, item, root, depth+1); err != nil {
				return fmt.Errorf("item %d: %w", index, err)
			}
		}
	}
	if unique, _ := schema["uniqueItems"].(bool); unique {
		seen := make(map[string]struct{}, len(value))
		for _, item := range value {
			canonical, err := canonicaljson.Marshal(item)
			if err != nil {
				return err
			}
			key := string(canonical)
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("array items are not unique")
			}
			seen[key] = struct{}{}
		}
	}
	return nil
}
func validateString(schema map[string]any, value string) error {
	length := utf8.RuneCountInString(value)
	if minimum, ok := schemaInteger(schema["minLength"]); ok && length < minimum {
		return fmt.Errorf("string is too short")
	}
	if maximum, ok := schemaInteger(schema["maxLength"]); ok && length > maximum {
		return fmt.Errorf("string is too long")
	}
	if pattern, ok := schema["pattern"].(string); ok {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid schema pattern")
		}
		if !compiled.MatchString(value) {
			return fmt.Errorf("string does not match pattern")
		}
	}
	if format, ok := schema["format"].(string); ok {
		switch format {
		case "uri":
			parsed, err := url.Parse(value)
			if err != nil || parsed.Scheme == "" {
				return fmt.Errorf("string is not an absolute URI")
			}
		case "uuid":
			if _, err := domain.ParseID(value); err != nil {
				return fmt.Errorf("string is not a canonical UUID")
			}
		case "date-time":
			if _, err := time.Parse(time.RFC3339, value); err != nil {
				return fmt.Errorf("string is not RFC3339 date-time")
			}
		}
	}
	return nil
}
func validateNumber(schema map[string]any, value json.Number) error {
	actual, ok := new(big.Rat).SetString(value.String())
	if !ok {
		return fmt.Errorf("invalid number")
	}
	if minimum, ok := schemaRat(schema["minimum"]); ok && actual.Cmp(minimum) < 0 {
		return fmt.Errorf("number is below minimum")
	}
	if maximum, ok := schemaRat(schema["maximum"]); ok && actual.Cmp(maximum) > 0 {
		return fmt.Errorf("number is above maximum")
	}
	return nil
}
func matchesTypes(raw, value any) bool {
	types := []string{}
	switch typed := raw.(type) {
	case string:
		types = []string{typed}
	case []any:
		for _, item := range typed {
			if name, ok := item.(string); ok {
				types = append(types, name)
			}
		}
	}
	for _, name := range types {
		switch name {
		case "null":
			if value == nil {
				return true
			}
		case "object":
			_, ok := value.(map[string]any)
			if ok {
				return true
			}
		case "array":
			_, ok := value.([]any)
			if ok {
				return true
			}
		case "string":
			_, ok := value.(string)
			if ok {
				return true
			}
		case "boolean":
			_, ok := value.(bool)
			if ok {
				return true
			}
		case "number":
			_, ok := value.(json.Number)
			if ok {
				return true
			}
		case "integer":
			if number, ok := value.(json.Number); ok {
				rat, valid := new(big.Rat).SetString(number.String())
				if valid && rat.IsInt() {
					return true
				}
			}
		}
	}
	return false
}
func resolvePointer(root any, path string) (any, error) {
	current := root
	for _, encoded := range strings.Split(path, "/") {
		part := strings.ReplaceAll(strings.ReplaceAll(encoded, "~1", "/"), "~0", "~")
		object, ok := current.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("schema reference traverses nonobject")
		}
		next, ok := object[part]
		if !ok {
			return nil, fmt.Errorf("schema reference %q is missing", path)
		}
		current = next
	}
	return current, nil
}
func equalJSON(left, right any) bool {
	a, ea := canonicaljson.Marshal(left)
	b, eb := canonicaljson.Marshal(right)
	return ea == nil && eb == nil && string(a) == string(b)
}
func schemaInteger(value any) (int, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.Atoi(number.String())
	return parsed, err == nil && parsed >= 0
}
func schemaRat(value any) (*big.Rat, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return nil, false
	}
	parsed, valid := new(big.Rat).SetString(number.String())
	return parsed, valid
}
