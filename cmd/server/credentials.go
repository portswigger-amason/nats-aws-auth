// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"time"

	"github.com/nats-io/jwt/v2"
)

// createNackUserClaims builds user claims for the NACK JetStream controller
// with $JS.API.> pub/sub permissions and _INBOX.> sub permissions.
func createNackUserClaims(userPubKey, accountPubKey string) *jwt.UserClaims {
	claims := jwt.NewUserClaims(userPubKey)
	claims.Name = "nack"
	claims.IssuedAt = time.Now().Unix()
	claims.IssuerAccount = accountPubKey

	claims.Permissions = jwt.Permissions{
		Pub: jwt.Permission{
			Allow: []string{"$JS.API.>"},
		},
		Sub: jwt.Permission{
			Allow: []string{"$JS.API.>", "_INBOX.>"},
		},
	}

	return claims
}
