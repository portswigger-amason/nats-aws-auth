package auth

import (
	"fmt"
	"testing"

	jwtpkg "github.com/portswigger/nats-aws-auth/internal/jwt"
)

// mockJWTValidator implements JWTValidator for testing
type mockJWTValidator struct {
	claims *jwtpkg.Claims
	err    error
}

func (m *mockJWTValidator) Validate(token string) (*jwtpkg.Claims, error) {
	return m.claims, m.err
}

// mockPermissionsProvider implements PermissionsProvider for testing
type mockPermissionsProvider struct {
	pub   []string
	sub   []string
	found bool
}

func (m *mockPermissionsProvider) GetPermissions(namespace, name string) ([]string, []string, bool) {
	return m.pub, m.sub, m.found
}

func TestK8sOIDCAuthorizer_ValidToken(t *testing.T) {
	validator := &mockJWTValidator{
		claims: &jwtpkg.Claims{Namespace: "default", ServiceAccount: "my-service"},
	}
	permProvider := &mockPermissionsProvider{
		pub:   []string{"default.>"},
		sub:   []string{"_INBOX.>", "default.>"},
		found: true,
	}

	authorizer := NewK8sOIDCAuthorizer(validator, permProvider)

	authorized, userName, perms, err := authorizer.Authorize("valid-k8s-jwt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !authorized {
		t.Fatal("expected authorized")
	}
	if userName != "default:my-service" {
		t.Fatalf("unexpected userName: %s", userName)
	}
	if len(perms.Pub) != 1 || perms.Pub[0] != "default.>" {
		t.Fatalf("unexpected pub perms: %v", perms.Pub)
	}
	if len(perms.Sub) != 2 {
		t.Fatalf("unexpected sub perms: %v", perms.Sub)
	}
}

func TestK8sOIDCAuthorizer_EmptyToken(t *testing.T) {
	validator := &mockJWTValidator{}
	permProvider := &mockPermissionsProvider{}

	authorizer := NewK8sOIDCAuthorizer(validator, permProvider)

	authorized, _, _, err := authorizer.Authorize("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authorized {
		t.Fatal("expected not authorized for empty token")
	}
}

func TestK8sOIDCAuthorizer_InvalidToken(t *testing.T) {
	validator := &mockJWTValidator{
		err: fmt.Errorf("invalid token"),
	}
	permProvider := &mockPermissionsProvider{}

	authorizer := NewK8sOIDCAuthorizer(validator, permProvider)

	authorized, _, _, err := authorizer.Authorize("bad-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authorized {
		t.Fatal("expected not authorized for invalid token")
	}
}

func TestK8sOIDCAuthorizer_SANotFound(t *testing.T) {
	validator := &mockJWTValidator{
		claims: &jwtpkg.Claims{Namespace: "default", ServiceAccount: "unknown-sa"},
	}
	permProvider := &mockPermissionsProvider{
		found: false,
	}

	authorizer := NewK8sOIDCAuthorizer(validator, permProvider)

	authorized, _, _, err := authorizer.Authorize("valid-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authorized {
		t.Fatal("expected not authorized when SA not found in cache")
	}
}

func TestAllowAllAuthorizer(t *testing.T) {
	authorizer := &AllowAllAuthorizer{}

	authorized, userName, perms, err := authorizer.Authorize("anything")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !authorized {
		t.Fatal("expected authorized")
	}
	if userName != "anonymous" {
		t.Fatalf("unexpected userName: %s", userName)
	}
	if len(perms.Pub) != 1 || perms.Pub[0] != ">" {
		t.Fatalf("unexpected pub perms: %v", perms.Pub)
	}
	if len(perms.Sub) != 1 || perms.Sub[0] != ">" {
		t.Fatalf("unexpected sub perms: %v", perms.Sub)
	}
}
