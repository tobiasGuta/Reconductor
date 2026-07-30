package scope

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

const legacyContainerScopePrefix = "/scope"

// CanonicalReference normalizes a logical relative scope reference for
// persistence. Absolute references are preserved because their meaning belongs
// to the process environment that created them.
func CanonicalReference(reference string) (string, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return "", fmt.Errorf("scope reference is required")
	}
	if isWindowsDriveRelative(reference) {
		return "", fmt.Errorf("Windows drive-relative scope reference %q is not portable; use an absolute or logical relative reference", reference)
	}
	if isAbsoluteReference(reference) || isLegacyContainerReference(reference) {
		return reference, nil
	}
	logical := strings.ReplaceAll(reference, `\`, "/")
	if containsParentSegment(logical) {
		return "", fmt.Errorf("scope reference %q contains parent traversal", reference)
	}
	logical = path.Clean(logical)
	if escapesRoot(logical) {
		return "", fmt.Errorf("scope reference %q escapes the configured scope root", reference)
	}
	if logical == "." {
		return "", fmt.Errorf("scope reference must identify a file")
	}
	return logical, nil
}

// ResolveReference converts a persisted scope reference into a path for the
// current process. Relative references are resolved beneath root when set.
// Legacy /scope/... references are mapped only when root is explicitly set.
func ResolveReference(reference, root string) (string, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return "", fmt.Errorf("scope reference is required")
	}
	root = strings.TrimSpace(root)

	if isLegacyContainerReference(reference) {
		logical := strings.TrimPrefix(strings.ReplaceAll(reference, `\`, "/"), "/")
		if containsParentSegment(logical) {
			return "", fmt.Errorf("scope reference %q contains parent traversal", reference)
		}
		if root == "" {
			return reference, nil
		}
		return resolveUnderRoot(root, logical, reference)
	}
	if isWindowsDriveRelative(reference) {
		return "", fmt.Errorf("Windows drive-relative scope reference %q is not portable; use an absolute or logical relative reference", reference)
	}
	if isWindowsAbsolute(reference) {
		if runtime.GOOS != "windows" {
			return "", fmt.Errorf("Windows absolute scope reference %q cannot be resolved on %s", reference, runtime.GOOS)
		}
		return filepath.Clean(reference), nil
	}
	if filepath.IsAbs(reference) {
		return filepath.Clean(reference), nil
	}

	logical, err := CanonicalReference(reference)
	if err != nil {
		return "", err
	}
	if root == "" {
		return filepath.Clean(filepath.FromSlash(logical)), nil
	}
	return resolveUnderRoot(root, logical, reference)
}

// LoadBurpReference resolves and loads a Burp-compatible scope reference.
func LoadBurpReference(reference, root string) (Scope, error) {
	resolved, err := ResolveReference(reference, root)
	if err != nil {
		return Scope{}, err
	}
	scope, err := LoadBurp(resolved)
	if err != nil {
		if os.IsNotExist(err) {
			return Scope{}, fmt.Errorf("scope reference %q resolved to %q does not exist: %w", reference, resolved, err)
		}
		return Scope{}, fmt.Errorf("scope reference %q resolved to %q: %w", reference, resolved, err)
	}
	return scope, nil
}

func resolveUnderRoot(root, logical, original string) (string, error) {
	rootPath, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", fmt.Errorf("resolve SCOPE_ROOT %q: %w", root, err)
	}
	logical = strings.ReplaceAll(logical, `\`, "/")
	if containsParentSegment(logical) {
		return "", fmt.Errorf("scope reference %q contains parent traversal", original)
	}
	logical = path.Clean(logical)
	if escapesRoot(logical) || logical == "." {
		return "", fmt.Errorf("scope reference %q escapes the configured scope root", original)
	}
	resolved := filepath.Join(rootPath, filepath.FromSlash(logical))
	relative, err := filepath.Rel(rootPath, resolved)
	if err != nil || escapesRoot(filepath.ToSlash(relative)) {
		return "", fmt.Errorf("scope reference %q escapes the configured scope root", original)
	}
	return resolved, nil
}

func isLegacyContainerReference(reference string) bool {
	normalized := strings.ReplaceAll(reference, `\`, "/")
	return normalized == legacyContainerScopePrefix || strings.HasPrefix(normalized, legacyContainerScopePrefix+"/")
}

func isAbsoluteReference(reference string) bool {
	return filepath.IsAbs(reference) || isWindowsAbsolute(reference)
}

func isWindowsAbsolute(reference string) bool {
	if strings.HasPrefix(reference, `\\`) {
		return true
	}
	return len(reference) >= 3 &&
		((reference[0] >= 'A' && reference[0] <= 'Z') || (reference[0] >= 'a' && reference[0] <= 'z')) &&
		reference[1] == ':' &&
		(reference[2] == '\\' || reference[2] == '/')
}

func isWindowsDriveRelative(reference string) bool {
	return len(reference) >= 2 &&
		((reference[0] >= 'A' && reference[0] <= 'Z') || (reference[0] >= 'a' && reference[0] <= 'z')) &&
		reference[1] == ':' &&
		(len(reference) == 2 || (reference[2] != '\\' && reference[2] != '/'))
}

func escapesRoot(logical string) bool {
	return logical == ".." || strings.HasPrefix(logical, "../")
}

func containsParentSegment(logical string) bool {
	for _, segment := range strings.Split(logical, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}
