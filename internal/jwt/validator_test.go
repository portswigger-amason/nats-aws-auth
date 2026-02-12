package jwt

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewValidatorFromFile_LoadsJWKS(t *testing.T) {
	jwksPath := filepath.Join("..", "..", "testdata", "jwks.json")

	validator, err := NewValidatorFromFile(jwksPath, "https://test-issuer.com", "test-audience")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if validator == nil {
		t.Fatal("expected validator to be created")
	}
}

func TestNewValidatorFromFile_FailsWithInvalidPath(t *testing.T) {
	validator, err := NewValidatorFromFile("/nonexistent/path/jwks.json", "https://test-issuer.com", "test-audience")

	if err == nil {
		t.Fatal("expected error for invalid JWKS path, got nil")
	}

	if validator != nil {
		t.Fatal("expected nil validator on error")
	}
}

func TestValidateToken_ValidToken(t *testing.T) {
	jwksPath := filepath.Join("..", "..", "testdata", "jwks.json")
	tokenPath := filepath.Join("..", "..", "testdata", "token.jwt")

	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("failed to read test token: %v", err)
	}
	tokenString := string(tokenBytes)

	validator, err := NewValidatorFromFile(
		jwksPath,
		"https://oidc.eks.eu-west-1.amazonaws.com/id/B88E7287E54DB073AC9CDC2FD1BE0969",
		"sts.amazonaws.com",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// Mock time to be within the token's validity window
	// Token: nbf=1763969878 (2025-11-24), exp=1764056278 (2025-11-25)
	validTime := time.Unix(1764000000, 0)
	validator.SetTimeFunc(func() time.Time {
		return validTime
	})

	claims, err := validator.ValidateToken(tokenString)
	if err != nil {
		t.Fatalf("expected valid token, got error: %v", err)
	}

	if claims == nil {
		t.Fatal("expected claims to be returned")
	}

	if claims.Namespace != "hakawai" {
		t.Errorf("expected namespace 'hakawai', got %q", claims.Namespace)
	}

	if claims.ServiceAccount != "hakawai-litellm-proxy" {
		t.Errorf("expected service account 'hakawai-litellm-proxy', got %q", claims.ServiceAccount)
	}
}

func TestValidateToken_ExpiredToken(t *testing.T) {
	jwksPath := filepath.Join("..", "..", "testdata", "jwks.json")
	tokenPath := filepath.Join("..", "..", "testdata", "token.jwt")

	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("failed to read test token: %v", err)
	}
	tokenString := string(tokenBytes)

	validator, err := NewValidatorFromFile(
		jwksPath,
		"https://oidc.eks.eu-west-1.amazonaws.com/id/B88E7287E54DB073AC9CDC2FD1BE0969",
		"sts.amazonaws.com",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// Mock time to be after the token expires
	futureTime := time.Unix(1767225600, 0) // 2026-01-01
	validator.SetTimeFunc(func() time.Time {
		return futureTime
	})

	_, err = validator.ValidateToken(tokenString)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}

	if !IsExpiredError(err) {
		t.Errorf("expected expired error, got %v", err)
	}
}

func TestValidateToken_InvalidSignature(t *testing.T) {
	jwksPath := filepath.Join("..", "..", "testdata", "jwks.json")

	validator, err := NewValidatorFromFile(jwksPath, "https://test-issuer.com", "test-audience")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	invalidToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImUzYjFkMTg1ZTBkNzk0MDU4YTYzNDZjMzJiMjU3NWFjMGVmYjYyMmUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL3Rlc3QtaXNzdWVyLmNvbSIsImF1ZCI6InRlc3QtYXVkaWVuY2UiLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTUxNjIzOTAyMiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJ0ZXN0Iiwic2VydmljZWFjY291bnQiOnsibmFtZSI6InRlc3Qtc2EifX19.invalidsignature"

	_, err = validator.ValidateToken(invalidToken)
	if err == nil {
		t.Fatal("expected error for invalid signature, got nil")
	}

	if !IsSignatureError(err) {
		t.Errorf("expected signature error, got %v", err)
	}
}

func TestValidateToken_WrongIssuer(t *testing.T) {
	jwksPath := filepath.Join("..", "..", "testdata", "jwks.json")
	tokenPath := filepath.Join("..", "..", "testdata", "token.jwt")

	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("failed to read test token: %v", err)
	}

	validator, err := NewValidatorFromFile(jwksPath, "https://wrong-issuer.com", "sts.amazonaws.com")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	validTime := time.Unix(1764000000, 0)
	validator.SetTimeFunc(func() time.Time {
		return validTime
	})

	_, err = validator.ValidateToken(string(tokenBytes))
	if err == nil {
		t.Fatal("expected error for wrong issuer, got nil")
	}

	if !IsClaimsError(err) {
		t.Errorf("expected claims validation error, got %v", err)
	}
}

func TestValidateToken_WrongAudience(t *testing.T) {
	jwksPath := filepath.Join("..", "..", "testdata", "jwks.json")
	tokenPath := filepath.Join("..", "..", "testdata", "token.jwt")

	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("failed to read test token: %v", err)
	}

	validator, err := NewValidatorFromFile(
		jwksPath,
		"https://oidc.eks.eu-west-1.amazonaws.com/id/B88E7287E54DB073AC9CDC2FD1BE0969",
		"wrong-audience",
	)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	validTime := time.Unix(1764000000, 0)
	validator.SetTimeFunc(func() time.Time {
		return validTime
	})

	_, err = validator.ValidateToken(string(tokenBytes))
	if err == nil {
		t.Fatal("expected error for wrong audience, got nil")
	}

	if !IsClaimsError(err) {
		t.Errorf("expected claims validation error, got %v", err)
	}
}
