package authorization

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

const (
	MaxPermissionLength = 160
	MaxRoleKeyLength    = 63
)

// ValidateRelativePermission accepts only canonical, colon-delimited permission keys.
func ValidateRelativePermission(value string) error {
	if value == "" || len(value) > MaxPermissionLength {
		return fmt.Errorf("permission must contain 1 to %d ASCII characters", MaxPermissionLength)
	}
	if !isASCII(value) || strings.ContainsAny(value, " /\\%\t\r\n") {
		return fmt.Errorf("permission must use lowercase ASCII colon-delimited segments")
	}
	segments := strings.Split(value, ":")
	for index, segment := range segments {
		if segment == "*" {
			if index != len(segments)-1 {
				return fmt.Errorf("wildcard must be the final complete segment")
			}
			continue
		}
		if !validSegment(segment) {
			return fmt.Errorf("permission segment %d is invalid", index+1)
		}
	}
	return nil
}

func ValidateRoleKey(value string) error {
	if value == "" || len(value) > MaxRoleKeyLength || !isASCII(value) {
		return fmt.Errorf("role key must contain 1 to %d ASCII characters", MaxRoleKeyLength)
	}
	if value[0] < 'a' || value[0] > 'z' {
		return fmt.Errorf("role key must start with a lowercase letter")
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '_' && character != '-' {
					return fmt.Errorf("role key contains an invalid character")
				}
			}
		}
	}
	return nil
}

func CanonicalScope(applicationID string, workspaceID *string, permission string) (string, error) {
	if err := ValidateRelativePermission(permission); err != nil {
		return "", err
	}
	if !validIdentifier(applicationID) {
		return "", fmt.Errorf("application identifier is invalid")
	}
	prefix := "/applications/" + applicationID
	if workspaceID != nil {
		if !validIdentifier(*workspaceID) {
			return "", fmt.Errorf("workspace identifier is invalid")
		}
		prefix += "/workspaces/" + *workspaceID
	}
	return prefix + "/" + strings.ReplaceAll(permission, ":", "/"), nil
}

func RoleMarker(applicationID string, workspaceID *string, roleKey string) (string, error) {
	if err := ValidateRoleKey(roleKey); err != nil {
		return "", err
	}
	prefix := "/applications/" + applicationID
	if workspaceID != nil {
		if !validIdentifier(*workspaceID) {
			return "", fmt.Errorf("workspace identifier is invalid")
		}
		prefix += "/workspaces/" + *workspaceID
	}
	return prefix + "/roles/" + roleKey, nil
}

// ValidateScopeClaim rejects non-canonical serialization as well as invalid paths.
func ValidateScopeClaim(scope, applicationID string) error {
	if scope == "" {
		return nil
	}
	if scope != strings.TrimSpace(scope) || strings.ContainsAny(scope, "\t\r\n") || strings.Contains(scope, "  ") {
		return fmt.Errorf("scope claim is not canonically space-delimited")
	}
	prefix := "/applications/" + applicationID + "/"
	seen := map[string]struct{}{}
	for _, value := range strings.Split(scope, " ") {
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("scope claim contains a duplicate value")
		}
		seen[value] = struct{}{}
		if protocolScope(value) {
			continue
		}
		if !strings.HasPrefix(value, prefix) || !validAbsolutePath(value) {
			return fmt.Errorf("scope %q is invalid for the application", value)
		}
	}
	return nil
}

func ValidateScopeValues(values []string, applicationID string) error {
	if len(values) == 0 {
		return nil
	}
	return ValidateScopeClaim(strings.Join(values, " "), applicationID)
}

func protocolScope(value string) bool {
	switch value {
	case "openid", "profile", "email", "offline_access":
		return true
	default:
		return false
	}
}

func Match(granted, wanted string) bool {
	if !validAbsolutePath(granted) || !validAbsolutePath(wanted) {
		return false
	}
	if granted == wanted {
		return true
	}
	if !strings.HasSuffix(granted, "/*") {
		return false
	}
	base := strings.TrimSuffix(granted, "/*")
	return wanted == base || strings.HasPrefix(wanted, base+"/")
}

func validAbsolutePath(value string) bool {
	if value == "" || value[0] != '/' || strings.ContainsAny(value, " :\\%\t\r\n") || !isASCII(value) {
		return false
	}
	segments := strings.Split(value[1:], "/")
	if len(segments) < 3 {
		return false
	}
	for index, segment := range segments {
		if segment == "*" {
			if index != len(segments)-1 {
				return false
			}
			continue
		}
		if !validSegment(segment) {
			return false
		}
	}
	return true
}

func validSegment(value string) bool {
	if value == "" || len(value) > 64 || value == "." || value == ".." {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		if index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func validIdentifier(value string) bool {
	_, err := uuid.Parse(value)
	return err == nil
}

func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}
