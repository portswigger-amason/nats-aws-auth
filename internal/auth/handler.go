// Package auth provides pluggable authorization backends for NATS auth callout.
package auth

import (
	jwtpkg "github.com/portswigger/nats-kms-auth/internal/jwt"
)

// JWTValidator defines the interface for JWT validation.
type JWTValidator interface {
	Validate(token string) (*jwtpkg.Claims, error)
}

// PermissionsProvider defines the interface for retrieving ServiceAccount permissions.
type PermissionsProvider interface {
	GetPermissions(namespace, name string) (pubPerms []string, subPerms []string, found bool)
}

// Permissions holds pub/sub permission lists.
type Permissions struct {
	Pub []string
	Sub []string
}

// Authorizer is the interface for auth backends.
type Authorizer interface {
	// Authorize inspects the connect token and returns authorization details.
	// Returns: authorized, userName, permissions, error
	Authorize(token string) (bool, string, Permissions, error)
}

// AllowAllAuthorizer accepts all connections with full permissions (for testing).
type AllowAllAuthorizer struct{}

func (a *AllowAllAuthorizer) Authorize(token string) (bool, string, Permissions, error) {
	return true, "anonymous", Permissions{
		Pub: []string{">"},
		Sub: []string{">"},
	}, nil
}
