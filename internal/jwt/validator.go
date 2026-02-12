// Package jwt provides JWT token validation and claims extraction for Kubernetes service account tokens.
package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

// Validator handles JWT validation using JWKS keys.
type Validator struct {
	jwks     *keyfunc.JWKS
	issuer   string
	audience string
	timeFunc func() time.Time
}

// Claims represents the validated JWT claims including Kubernetes-specific fields.
type Claims struct {
	Namespace      string
	ServiceAccount string
	Issuer         string
	Audience       []string
	ExpiresAt      time.Time
	IssuedAt       time.Time
	NotBefore      time.Time
}

var (
	ErrExpiredToken     = errors.New("token has expired")
	ErrInvalidSignature = errors.New("invalid token signature")
	ErrInvalidClaims    = errors.New("invalid token claims")
	ErrMissingK8sClaims = errors.New("missing kubernetes claims")
)

// NewValidatorFromURL creates a new JWT validator that fetches JWKS from an HTTP URL.
func NewValidatorFromURL(jwksURL, issuer, audience string) (*Validator, error) {
	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from URL: %w", err)
	}

	return &Validator{
		jwks:     jwks,
		issuer:   issuer,
		audience: audience,
		timeFunc: time.Now,
	}, nil
}

// NewValidatorFromFile creates a new JWT validator that loads JWKS from a file.
func NewValidatorFromFile(jwksPath, issuer, audience string) (*Validator, error) {
	jwksData, err := os.ReadFile(jwksPath) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS file: %w", err)
	}

	jwks, err := keyfunc.NewJSON(jwksData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return &Validator{
		jwks:     jwks,
		issuer:   issuer,
		audience: audience,
		timeFunc: time.Now,
	}, nil
}

// SetTimeFunc sets a custom time function for testing purposes.
func (v *Validator) SetTimeFunc(fn func() time.Time) {
	v.timeFunc = fn
}

// Validate validates a JWT token and returns the extracted claims.
func (v *Validator) Validate(token string) (*Claims, error) {
	return v.ValidateToken(token)
}

// ValidateToken validates a JWT token and returns the extracted claims.
func (v *Validator) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.Parse(tokenString, v.jwks.Keyfunc, jwt.WithTimeFunc(v.timeFunc))
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("%w: %v", ErrExpiredToken, err)
		}
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, ErrInvalidSignature
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to extract claims")
	}

	if err := v.validateStandardClaims(mapClaims); err != nil {
		return nil, err
	}

	claims, err := v.extractK8sClaims(mapClaims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func (v *Validator) validateStandardClaims(claims jwt.MapClaims) error {
	if err := validateIssuer(claims, v.issuer); err != nil {
		return err
	}
	if err := validateAudience(claims, v.audience); err != nil {
		return err
	}
	if err := validateTimeClaims(claims, v.timeFunc); err != nil {
		return err
	}
	return nil
}

func validateIssuer(claims jwt.MapClaims, expectedIssuer string) error {
	iss, ok := claims["iss"].(string)
	if !ok || iss != expectedIssuer {
		return fmt.Errorf("%w: issuer mismatch (expected %q, got %q)", ErrInvalidClaims, expectedIssuer, iss)
	}
	return nil
}

func validateAudience(claims jwt.MapClaims, expectedAudience string) error {
	aud, ok := claims["aud"]
	if !ok {
		return fmt.Errorf("%w: missing audience", ErrInvalidClaims)
	}

	var audiences []string
	switch a := aud.(type) {
	case string:
		audiences = []string{a}
	case []interface{}:
		for _, item := range a {
			if str, ok := item.(string); ok {
				audiences = append(audiences, str)
			}
		}
	default:
		return fmt.Errorf("%w: invalid audience format", ErrInvalidClaims)
	}

	for _, a := range audiences {
		if a == expectedAudience {
			return nil
		}
	}
	return fmt.Errorf("%w: audience mismatch (expected %q)", ErrInvalidClaims, expectedAudience)
}

func validateTimeClaims(claims jwt.MapClaims, timeFunc func() time.Time) error {
	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("%w: missing or invalid exp claim", ErrInvalidClaims)
	}
	if timeFunc().Unix() > int64(exp) {
		return ErrExpiredToken
	}

	if nbf, ok := claims["nbf"].(float64); ok {
		if timeFunc().Unix() < int64(nbf) {
			return fmt.Errorf("%w: token not yet valid", ErrInvalidClaims)
		}
	}

	if iat, ok := claims["iat"].(float64); ok {
		if timeFunc().Unix()+60 < int64(iat) {
			return fmt.Errorf("%w: issued-at is in the future", ErrInvalidClaims)
		}
	}

	return nil
}

func extractK8sMap(claims jwt.MapClaims) (map[string]interface{}, error) {
	k8sData, ok := claims["kubernetes.io"]
	if !ok {
		return nil, fmt.Errorf("%w: kubernetes.io claim missing", ErrMissingK8sClaims)
	}

	k8sMap, ok := k8sData.(map[string]interface{})
	if ok {
		return k8sMap, nil
	}

	jsonData, err := json.Marshal(k8sData)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid kubernetes.io format", ErrMissingK8sClaims)
	}
	if err := json.Unmarshal(jsonData, &k8sMap); err != nil {
		return nil, fmt.Errorf("%w: invalid kubernetes.io format", ErrMissingK8sClaims)
	}
	return k8sMap, nil
}

func extractServiceAccountName(k8sMap map[string]interface{}) (string, error) {
	saData, ok := k8sMap["serviceaccount"]
	if !ok {
		return "", fmt.Errorf("%w: serviceaccount claim missing", ErrMissingK8sClaims)
	}

	saMap, ok := saData.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: invalid serviceaccount format", ErrMissingK8sClaims)
	}

	saName, ok := saMap["name"].(string)
	if !ok || saName == "" {
		return "", fmt.Errorf("%w: serviceaccount name missing or empty", ErrMissingK8sClaims)
	}

	return saName, nil
}

func extractAudienceList(claims jwt.MapClaims) []string {
	aud, ok := claims["aud"]
	if !ok {
		return nil
	}

	switch a := aud.(type) {
	case string:
		return []string{a}
	case []interface{}:
		var audiences []string
		for _, item := range a {
			if str, ok := item.(string); ok {
				audiences = append(audiences, str)
			}
		}
		return audiences
	default:
		return nil
	}
}

func (v *Validator) extractK8sClaims(claims jwt.MapClaims) (*Claims, error) {
	k8sMap, err := extractK8sMap(claims)
	if err != nil {
		return nil, err
	}

	namespace, ok := k8sMap["namespace"].(string)
	if !ok || namespace == "" {
		return nil, fmt.Errorf("%w: namespace claim missing or empty", ErrMissingK8sClaims)
	}

	saName, err := extractServiceAccountName(k8sMap)
	if err != nil {
		return nil, err
	}

	issuer, _ := claims["iss"].(string)

	result := &Claims{
		Namespace:      namespace,
		ServiceAccount: saName,
		Issuer:         issuer,
		Audience:       extractAudienceList(claims),
	}

	if exp, ok := claims["exp"].(float64); ok {
		result.ExpiresAt = time.Unix(int64(exp), 0)
	}
	if iat, ok := claims["iat"].(float64); ok {
		result.IssuedAt = time.Unix(int64(iat), 0)
	}
	if nbf, ok := claims["nbf"].(float64); ok {
		result.NotBefore = time.Unix(int64(nbf), 0)
	}

	return result, nil
}

// IsExpiredError checks if the error is due to token expiration.
func IsExpiredError(err error) bool {
	return errors.Is(err, ErrExpiredToken)
}

// IsSignatureError checks if the error is due to invalid signature.
func IsSignatureError(err error) bool {
	return errors.Is(err, ErrInvalidSignature)
}

// IsClaimsError checks if the error is due to invalid claims.
func IsClaimsError(err error) bool {
	return errors.Is(err, ErrInvalidClaims)
}
