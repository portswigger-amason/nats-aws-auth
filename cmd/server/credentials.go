// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"fmt"
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

// formatCredentials produces a NATS .creds file from a JWT and nkey seed.
func formatCredentials(userJWT, seed string) string {
	return fmt.Sprintf(`-----BEGIN NATS USER JWT-----
%s
------END NATS USER JWT------

-----BEGIN USER NKEY SEED-----
%s
------END USER NKEY SEED------
`, userJWT, seed)
}
