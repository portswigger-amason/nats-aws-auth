// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"go.uber.org/zap"
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

// runGenerateCredentials generates NACK credentials signed by the APP account KMS key.
func runGenerateCredentials(ctx context.Context, logger *zap.Logger, region, appAccountKeyAlias, outputDir string) {
	client := setupAWSClient(ctx, logger, region)

	logger.Info("Generating NACK credentials...")

	// Step 1: Get or create APP account key in KMS
	logger.Info("Getting/creating APP account key in KMS...", zap.String("alias", appAccountKeyAlias))
	appAccountKey, appExisted, err := getOrCreateKMSKey(ctx, client, nkeys.PrefixByteAccount, appAccountKeyAlias)
	if err != nil {
		logger.Fatal("Failed to get/create APP account key", zap.Error(err))
	}
	logKeyStatus(logger, "APP Account", appAccountKey, appExisted)

	// Step 2: Generate NACK user keypair
	logger.Info("Generating NACK user keypair...")
	nackKey, err := createLocalKey(nkeys.PrefixByteUser)
	if err != nil {
		logger.Fatal("Failed to create NACK user key", zap.Error(err))
	}
	logger.Debug("NACK User Public Key", zap.String("public_key", nackKey.PublicKey))

	// Step 3: Create NACK user JWT signed by APP account key via KMS
	logger.Info("Creating NACK user JWT (signed by APP account via KMS)...")
	nackClaims := createNackUserClaims(nackKey.PublicKey, appAccountKey.PublicKey)
	appAccountKP := &dummyKeyPair{pubKey: appAccountKey.PublicKey}
	appAccountSigner := createKMSSigner(ctx, client, appAccountKey.KeyID)

	nackJWT, err := nackClaims.EncodeWithSigner(appAccountKP, appAccountSigner)
	if err != nil {
		logger.Fatal("Failed to encode NACK user JWT", zap.Error(err))
	}
	logger.Debug("NACK user JWT created successfully")

	// Step 4: Write credentials file
	logger.Info("Writing NACK credentials file...")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logger.Fatal("Failed to create output directory", zap.Error(err))
	}

	credsContent := formatCredentials(nackJWT, nackKey.Seed)
	credsPath := outputDir + "/nack.creds"
	if err := os.WriteFile(credsPath, []byte(credsContent), 0600); err != nil {
		logger.Fatal("Failed to write NACK credentials", zap.Error(err))
	}
	logger.Debug("NACK credentials written", zap.String("path", credsPath))

	logger.Info("Credential generation complete!")
	logger.Info("Generated files",
		zap.String("credentials", fmt.Sprintf("%s/nack.creds", outputDir)))
}
