// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/portswigger/nats-aws-auth/internal/auth"
	"go.uber.org/zap"
)

// AuthCalloutHandler handles NATS auth callout requests
type AuthCalloutHandler struct {
	logger         *zap.Logger
	signingKP      nkeys.KeyPair
	authAccountPub string
	targetAccount  string
	authorizer     auth.Authorizer
}

// HandleAuthRequest processes an incoming auth callout request
func (h *AuthCalloutHandler) HandleAuthRequest(msg *nats.Msg) {
	start := time.Now()
	status := "error"
	defer func() {
		authCalloutDuration.Observe(time.Since(start).Seconds())
		authCalloutRequests.WithLabelValues(status).Inc()
	}()

	h.logger.Info("Received auth request")

	authClaims, err := decodeAuthRequest(msg.Data)
	if err != nil {
		h.logger.Error("Failed to decode auth request", zap.Error(err))
		h.respondWithError(msg, "", "failed to decode authorization request")
		return
	}

	h.logAuthRequest(authClaims)

	authorized, userName, permissions := h.authorize(authClaims)

	if !authorized {
		h.logger.Info("Authorization denied")
		status = "denied"
		h.respondWithError(msg, authClaims.UserNkey, "authorization denied")
		return
	}

	h.logger.Info("User authorized",
		zap.String("user", userName),
		zap.String("target_account", h.targetAccount),
		zap.String("server_id", authClaims.Server.ID))

	userJWT, err := h.createUserJWTForCallout(authClaims.UserNkey, userName, permissions, authClaims.Server.ID)
	if err != nil {
		h.logger.Error("Failed to create user JWT", zap.Error(err))
		h.respondWithError(msg, authClaims.UserNkey, "internal error creating user JWT")
		return
	}
	h.logger.Debug("User JWT created")

	responseJWT, err := h.createAuthResponse(authClaims, userJWT)
	if err != nil {
		h.logger.Error("Failed to create auth response", zap.Error(err))
		h.respondWithError(msg, authClaims.UserNkey, "internal error creating response")
		return
	}

	if err := msg.Respond([]byte(responseJWT)); err != nil {
		h.logger.Error("Failed to send response", zap.Error(err))
		return
	}

	status = "authorized"
	h.logger.Debug("Response sent successfully")
}

func decodeAuthRequest(data []byte) (*jwt.AuthorizationRequestClaims, error) {
	authRequestJWT := string(data)
	return jwt.DecodeAuthorizationRequestClaims(authRequestJWT)
}

func (h *AuthCalloutHandler) logAuthRequest(authClaims *jwt.AuthorizationRequestClaims) {
	userNKey := authClaims.UserNkey
	clientInfo := authClaims.ClientInformation
	connect := authClaims.ConnectOptions

	authMethod := determineAuthMethod(connect)
	h.logger.Debug("Auth request details",
		zap.String("user_nkey", userNKey),
		zap.String("client_name", clientInfo.Name),
		zap.String("client_host", clientInfo.Host),
		zap.String("auth_method", authMethod))
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
		h.logger.Error("Authorizer error", zap.Error(err))
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
		h.logger.Error("Cannot send error response (no user nkey)", zap.String("error", errMsg))
		return
	}

	response := jwt.NewAuthorizationResponseClaims(userNkey)
	response.Error = errMsg
	response.IssuerAccount = h.authAccountPub

	token, err := response.Encode(h.signingKP)
	if err != nil {
		h.logger.Error("Failed to encode error response", zap.Error(err))
		return
	}

	if err := msg.Respond([]byte(token)); err != nil {
		h.logger.Error("Failed to send error response", zap.Error(err))
	}
}
