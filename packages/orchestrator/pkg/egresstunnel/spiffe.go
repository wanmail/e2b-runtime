package egresstunnel

import (
	"fmt"
	"strings"
)

// ID is the SPIFFE URI SAN (and later JWT sub) for a sandbox execution.
func ID(trustDomain, teamID, sandboxID, executionID string) (string, error) {
	if err := checkPathSegment("trust_domain", trustDomain); err != nil {
		return "", err
	}
	if err := checkPathSegment("team_id", teamID); err != nil {
		return "", err
	}
	if err := checkPathSegment("sandbox_id", sandboxID); err != nil {
		return "", err
	}
	if err := checkPathSegment("execution_id", executionID); err != nil {
		return "", err
	}

	return fmt.Sprintf("spiffe://%s/ns/%s/sbx/%s/exec/%s", trustDomain, teamID, sandboxID, executionID), nil
}

func checkPathSegment(name, value string) error {
	if value == "" {
		return fmt.Errorf("spiffe %s must not be empty", name)
	}
	if strings.ContainsAny(value, "/#?@") {
		return fmt.Errorf("spiffe %s contains illegal characters", name)
	}

	return nil
}
