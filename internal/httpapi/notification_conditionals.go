package httpapi

import (
	"regexp"
	"strings"
)

var notificationConditionalPattern = regexp.MustCompile(`{{\s*(#if\b[^{}]*|/if\s*)}}`)

// Evaluate only template source, before substitution: variable values cannot
// introduce template instructions or bypass HTML escaping.
func renderNotificationConditionals(source string, variables map[string]any) (string, error) {
	var out strings.Builder
	active := []bool{true}
	position := 0
	for _, bounds := range notificationConditionalPattern.FindAllStringSubmatchIndex(source, -1) {
		if active[len(active)-1] {
			out.WriteString(source[position:bounds[0]])
		}
		tag := strings.TrimSpace(source[bounds[2]:bounds[3]])
		if tag == "/if" {
			if len(active) == 1 {
				return "", &templateVariableError{name: "conditional", reason: "has an unmatched closing block"}
			}
			active = active[:len(active)-1]
		} else {
			name := strings.TrimSpace(strings.TrimPrefix(tag, "#if"))
			match := notificationVariablePattern.FindStringSubmatch("{{" + name + "}}")
			if len(match) != 2 || match[0] != "{{"+name+"}}" || len(active) > 16 {
				return "", &templateVariableError{name: "conditional", reason: "requires one variable and at most 16 nested blocks"}
			}
			value, exists := variables[name]
			if !exists {
				return "", &templateVariableError{name: name, reason: "is missing or undeclared"}
			}
			present := strings.TrimSpace(toString(value)) != ""
			if flag, ok := value.(bool); ok {
				present = flag
			}
			active = append(active, active[len(active)-1] && present)
		}
		position = bounds[1]
	}
	if len(active) != 1 {
		return "", &templateVariableError{name: "conditional", reason: "has an unclosed block"}
	}
	out.WriteString(source[position:])
	return out.String(), nil
}
