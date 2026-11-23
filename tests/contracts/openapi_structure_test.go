package contracts

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Validate the OpenAPI 3.1 structural contracts used by this document. Schema
// Objects are distinct from Response Objects; every local JSON Pointer must
// resolve, including references nested in schemas, arrays and media types.
func validateOpenAPIStructure(raw []byte) error {
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return err
	}
	if version, _ := doc["openapi"].(string); !strings.HasPrefix(version, "3.1.") {
		return fmt.Errorf("OpenAPI 3.1 required")
	}
	resolve := func(ref string) (any, error) {
		var value any = doc
		if !strings.HasPrefix(ref, "#/") {
			return nil, fmt.Errorf("invalid local reference %q", ref)
		}
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			switch container := value.(type) {
			case map[string]any:
				var ok bool
				value, ok = container[part]
				if !ok {
					return nil, fmt.Errorf("unresolved reference %s", ref)
				}
			case []any:
				index, err := strconv.Atoi(part)
				if err != nil || index < 0 || index >= len(container) {
					return nil, fmt.Errorf("unresolved reference %s", ref)
				}
				value = container[index]
			default:
				return nil, fmt.Errorf("unresolved reference %s", ref)
			}
		}
		return value, nil
	}
	var walk func(any) error
	walk = func(node any) error {
		switch v := node.(type) {
		case map[string]any:
			for key, value := range v {
				if key == "$ref" {
					ref, ok := value.(string)
					if !ok {
						return fmt.Errorf("reference must be a string")
					}
					if strings.HasPrefix(ref, "#") {
						if _, err := resolve(ref); err != nil {
							return err
						}
					}
				}
				if err := walk(value); err != nil {
					return err
				}
			}
		case []any:
			for _, value := range v {
				if err := walk(value); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(doc); err != nil {
		return err
	}
	var response func(any, map[string]bool) error
	response = func(value any, seen map[string]bool) error {
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("Response Object must be a mapping")
		}
		if rawRef, ok := object["$ref"]; ok {
			ref, ok := rawRef.(string)
			if !ok || !strings.HasPrefix(ref, "#/components/responses/") {
				return fmt.Errorf("response reference must target components.responses")
			}
			if seen[ref] {
				return fmt.Errorf("cyclic response reference %s", ref)
			}
			seen[ref] = true
			target, err := resolve(ref)
			if err != nil {
				return err
			}
			return response(target, seen)
		}
		if _, ok := object["description"].(string); !ok {
			return fmt.Errorf("Response Object requires string description")
		}
		for key := range object {
			if key != "description" && key != "headers" && key != "content" && key != "links" && !strings.HasPrefix(key, "x-") {
				return fmt.Errorf("invalid Response Object field %s", key)
			}
		}
		return nil
	}
	var problems []string
	components, _ := doc["components"].(map[string]any)
	if responses, ok := components["responses"].(map[string]any); ok {
		for name, value := range responses {
			if err := response(value, map[string]bool{}); err != nil {
				problems = append(problems, fmt.Sprintf("components.responses.%s: %s", name, err))
			}
		}
	}
	paths, _ := doc["paths"].(map[string]any)
	for path, rawItem := range paths {
		item, ok := rawItem.(map[string]any)
		if !ok {
			return fmt.Errorf("path item must be a mapping")
		}
		for method, rawOperation := range item {
			switch method {
			case "get", "post", "put", "patch", "delete", "options", "head", "trace":
			default:
				continue
			}
			operation, ok := rawOperation.(map[string]any)
			if !ok {
				return fmt.Errorf("operation must be a mapping")
			}
			responses, ok := operation["responses"].(map[string]any)
			if !ok || len(responses) == 0 {
				return fmt.Errorf("operation responses required")
			}
			for status, value := range responses {
				if status != "default" && (len(status) != 3 || status[0] < '1' || status[0] > '5' || (status[1:] != "XX" && (status[1] < '0' || status[1] > '9' || status[2] < '0' || status[2] > '9'))) {
					return fmt.Errorf("invalid HTTP response status %q", status)
				}
				if err := response(value, map[string]bool{}); err != nil {
					problems = append(problems, fmt.Sprintf("%s %s %s: %s", method, path, status, err))
				}
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%s", strings.Join(problems, "\n"))
	}
	return nil
}

func TestOpenAPIReferencesAndResponseObjects(t *testing.T) {
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err = validateOpenAPIStructure(raw); err != nil {
		t.Fatal(err)
	}
}
func TestOpenAPIStructuralValidatorRejectsBrokenContracts(t *testing.T) {
	valid := `openapi: 3.1.0
paths:
  /items:
    get:
      responses:
        '200': {$ref: '#/components/responses/OK'}
components:
  responses:
    OK:
      description: Read items
      content:
        application/json:
          schema: {$ref: '#/components/schemas/Item~1kind'}
  schemas:
    Item/kind: {type: object}
`
	if err := validateOpenAPIStructure([]byte(valid)); err != nil {
		t.Fatal("valid escaped JSON Pointer rejected", err)
	}
	for name, broken := range map[string]string{
		"unresolved nested schema":   strings.Replace(valid, "Item~1kind'", "Missing'", 1),
		"schema in response section": strings.Replace(valid, "description: Read items", "type: object", 1),
		"schema fields in response":  strings.Replace(valid, "description: Read items", "description: Read items\n      properties: {}", 1),
		"response ref to schema":     strings.Replace(valid, "#/components/responses/OK", "#/components/schemas/Item~1kind", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateOpenAPIStructure([]byte(broken)); err == nil {
				t.Fatal("invalid OpenAPI contract accepted")
			}
		})
	}
}
