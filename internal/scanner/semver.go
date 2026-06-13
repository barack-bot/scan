package scanner

import (
	"strconv"
	"strings"
)

// parseVersion parses a version string like "2.4.49" into a slice of integers.
// Returns nil if the string cannot be parsed.
func parseVersion(v string) []int {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ".")
	var result []int
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		result = append(result, n)
	}
	return result
}

// compareVersions compares two version slices.
// Returns -1 if a < b, 1 if a > b, 0 if equal.
func compareVersions(a, b []int) int {
	maxLength := len(a)
	if len(b) > maxLength {
		maxLength = len(b)
	}
	for i := 0; i < maxLength; i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

// VersionAffected checks whether a given version string falls within a constraint string.
// Supported constraints:
//   - "2.4.49" (exact match)
//   - "<2.4.50" (less than)
//   - "<=2.4.49" (less than or equal)
//   - ">2.4.48" (greater than)
//   - ">=2.4.49" (greater than or equal)
//   - "2.4.49,2.4.50" or "2.4.49-2.4.50" (range, inclusive)
//   - ">=2.2.0 <2.2.33" (compound constraints — multiple operators separated by space)
//
// Returns true if the version matches the constraint.
func VersionAffected(version, constraint string) bool {
	verParts := parseVersion(version)
	if verParts == nil {
		return false
	}

	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		return true // No constraint specified, assume affected
	}

	// Handle compound constraints: ">=2.2.0 <2.2.33"
	// Split by spaces to check multiple operators independently
	parts := strings.Fields(constraint)
	if len(parts) > 1 {
		// If the constraint has spaces, it's a compound constraint like ">=2.2.0 <2.2.33"
		// or could also be ">=2.2.0 and <2.2.33" — we just check each piece
		for _, part := range parts {
			if part == "and" || part == "&&" {
				continue
			}
			if !checkSingleConstraint(verParts, part) {
				return false
			}
		}
		return true
	}

	// Single constraint — delegate to the single constraint checker
	return checkSingleConstraint(verParts, constraint)
}

// checkSingleConstraint checks a version against a single constraint string.
// Handles: "2.4.49", "<2.4.50", "<=2.4.49", ">2.4.48", ">=2.4.49", "=2.4.49"
func checkSingleConstraint(verParts []int, constraint string) bool {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		return true
	}

	// Handle range constraints: "2.4.49,2.4.50" or "2.4.49-2.4.50"
	if strings.Contains(constraint, ",") || strings.Contains(constraint, "-") {
		var sep string
		if strings.Contains(constraint, ",") {
			sep = ","
		} else {
			sep = "-"
		}
		parts := strings.SplitN(constraint, sep, 2)
		if len(parts) == 2 {
			lowParts := parseVersion(parts[0])
			highParts := parseVersion(parts[1])
			if lowParts != nil && highParts != nil {
				return compareVersions(verParts, lowParts) >= 0 &&
					compareVersions(verParts, highParts) <= 0
			}
		}
		return false
	}

	// Handle single operator constraints
	if strings.HasPrefix(constraint, ">=") {
		return compareVersions(verParts, parseVersion(constraint[2:])) >= 0
	}
	if strings.HasPrefix(constraint, "<=") {
		return compareVersions(verParts, parseVersion(constraint[2:])) <= 0
	}
	if strings.HasPrefix(constraint, ">") {
		return compareVersions(verParts, parseVersion(constraint[1:])) > 0
	}
	if strings.HasPrefix(constraint, "<") {
		return compareVersions(verParts, parseVersion(constraint[1:])) < 0
	}
	if strings.HasPrefix(constraint, "=") {
		return compareVersions(verParts, parseVersion(constraint[1:])) == 0
	}

	// Default: exact match
	return compareVersions(verParts, parseVersion(constraint)) == 0
}
