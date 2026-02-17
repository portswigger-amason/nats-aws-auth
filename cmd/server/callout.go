// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/portswigger/nats-aws-auth/internal/auth"
)

// AuthCalloutHandler handles NATS auth callout requests
type AuthCalloutHandler struct {
	signingKP      nkeys.KeyPair
	authAccountPub string
	targetAccount  string
	authorizer     auth.Authorizer
}

// HandleAuthRequest processes an incoming auth callout request
func (h *AuthCalloutHandler) HandleAuthRequest(msg *nats.Msg) {
	log.Printf("[AUTH] Received auth request")

	authClaims, err := decodeAuthRequest(msg.Data)
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to decode auth request: %v", err)
		h.respondWithError(msg, "", "failed to decode authorization request")
		return
	}

	logAuthRequest(authClaims)

	authorized, userName, permissions := h.authorize(authClaims)

	if !authorized {
		log.Printf("[AUTH]   Decision: DENIED")
		h.respondWithError(msg, authClaims.UserNkey, "authorization denied")
		return
	}

	log.Printf("[AUTH]   Decision: AUTHORIZED as '%s'", userName)
	log.Printf("[AUTH]   Target account: %s", h.targetAccount)
	log.Printf("[AUTH]   Server ID (audience): %s", authClaims.Server.ID)

	userJWT, err := h.createUserJWTForCallout(authClaims.UserNkey, userName, permissions, authClaims.Server.ID)
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to create user JWT: %v", err)
		h.respondWithError(msg, authClaims.UserNkey, "internal error creating user JWT")
		return
	}
	log.Printf("[AUTH]   User JWT created")

	responseJWT, err := h.createAuthResponse(authClaims, userJWT)
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to create auth response: %v", err)
		h.respondWithError(msg, authClaims.UserNkey, "internal error creating response")
		return
	}

	if err := msg.Respond([]byte(responseJWT)); err != nil {
		log.Printf("[AUTH] ERROR: Failed to send response: %v", err)
		return
	}

	log.Printf("[AUTH]   Response sent successfully")
}

func decodeAuthRequest(data []byte) (*jwt.AuthorizationRequestClaims, error) {
	authRequestJWT := string(data)
	return jwt.DecodeAuthorizationRequestClaims(authRequestJWT)
}

func logAuthRequest(authClaims *jwt.AuthorizationRequestClaims) {
	userNKey := authClaims.UserNkey
	clientInfo := authClaims.ClientInformation
	connect := authClaims.ConnectOptions

	log.Printf("[AUTH]   User NKey: %s", userNKey)
	log.Printf("[AUTH]   Client: %s (host: %s)", clientInfo.Name, clientInfo.Host)

	authMethod := determineAuthMethod(connect)
	log.Printf("[AUTH]   Auth method: %s", authMethod)
}

func determineAuthMethod(connect jwt.ConnectOptions) string {
	if connect.Token != "" {
		return "bearer_token"
	} else if connect.Username != "" {
		return "username_password"
	} else if connect.JWT != "" {
		return "jwt"
	} else if connect.Nkey != "" {
		return "nkey"
	}
	return "none"
}

// authorize makes the authorization decision using the pluggable Authorizer
func (h *AuthCalloutHandler) authorize(claims *jwt.AuthorizationRequestClaims) (bool, string, jwt.UserPermissionLimits) {
	token := claims.ConnectOptions.Token
	if token == "" {
		token = claims.ConnectOptions.JWT
	}

	authorized, userName, perms, err := h.authorizer.Authorize(token)
	if err != nil {
		log.Printf("[AUTH] Authorizer error: %v", err)
		return false, "", jwt.UserPermissionLimits{}
	}

	if !authorized {
		return false, "", jwt.UserPermissionLimits{}
	}

	permissions := convertPermissions(perms)
	return true, userName, permissions
}

func convertPermissions(perms auth.Permissions) jwt.UserPermissionLimits {
	return jwt.UserPermissionLimits{
		Permissions: jwt.Permissions{
			Pub: jwt.Permission{
				Allow: perms.Pub,
			},
			Sub: jwt.Permission{
				Allow: perms.Sub,
			},
		},
		Limits: jwt.Limits{
			NatsLimits: jwt.NatsLimits{
				Subs:    -1,
				Data:    -1,
				Payload: -1,
			},
		},
	}
}

// createUserJWTForCallout creates a user JWT for the authorized user
func (h *AuthCalloutHandler) createUserJWTForCallout(userNKey, userName string, permissions jwt.UserPermissionLimits, audience string) (string, error) {
	claims := jwt.NewUserClaims(userNKey)
	claims.Name = userName
	claims.IssuedAt = time.Now().Unix()
	claims.IssuerAccount = h.targetAccount

	if audience != "" {
		claims.Audience = audience
	}

	claims.Permissions = permissions.Permissions
	claims.Limits = permissions.Limits
	claims.BearerToken = false

	token, err := claims.Encode(h.signingKP)
	if err != nil {
		return "", fmt.Errorf("failed to encode user claims: %w", err)
	}

	return token, nil
}

// createAuthResponse creates the authorization response JWT
func (h *AuthCalloutHandler) createAuthResponse(request *jwt.AuthorizationRequestClaims, userJWT string) (string, error) {
	response := jwt.NewAuthorizationResponseClaims(request.UserNkey)
	response.Audience = request.Server.ID
	response.Jwt = userJWT
	response.IssuerAccount = h.authAccountPub

	token, err := response.Encode(h.signingKP)
	if err != nil {
		return "", fmt.Errorf("failed to encode response: %w", err)
	}

	return token, nil
}

// respondWithError sends an error response. userNkey may be empty when the
// request could not be decoded; in that case we log and bail because
// jwt.NewAuthorizationResponseClaims requires a non-empty subject.
func (h *AuthCalloutHandler) respondWithError(msg *nats.Msg, userNkey, errMsg string) {
	if userNkey == "" {
		log.Printf("[AUTH] ERROR: Cannot send error response (no user nkey): %s", errMsg)
		return
	}

	response := jwt.NewAuthorizationResponseClaims(userNkey)
	response.Error = errMsg
	response.IssuerAccount = h.authAccountPub

	token, err := response.Encode(h.signingKP)
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to encode error response: %v", err)
		return
	}

	if err := msg.Respond([]byte(token)); err != nil {
		log.Printf("[AUTH] ERROR: Failed to send error response: %v", err)
	}
}
