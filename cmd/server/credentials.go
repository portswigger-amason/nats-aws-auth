// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
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
func runGenerateCredentials(ctx context.Context, region, appAccountKeyAlias, outputDir string) {
	client := setupAWSClient(ctx, region)

	log.Println("Generating NACK credentials...")
	log.Println()

	// Step 1: Get or create APP account key in KMS
	log.Printf("Step 1: Getting/creating APP account key in KMS (alias: %s)...", appAccountKeyAlias)
	appAccountKey, appExisted, err := getOrCreateKMSKey(ctx, client, nkeys.PrefixByteAccount, appAccountKeyAlias)
	if err != nil {
		log.Fatalf("Failed to get/create APP account key: %v", err)
	}
	logKeyStatus("APP Account", appAccountKey, appExisted)

	// Step 2: Generate NACK user keypair
	log.Println("Step 2: Generating NACK user keypair...")
	nackKey, err := createLocalKey(nkeys.PrefixByteUser)
	if err != nil {
		log.Fatalf("Failed to create NACK user key: %v", err)
	}
	log.Printf("  NACK User Public Key: %s", nackKey.PublicKey)
	log.Println()

	// Step 3: Create NACK user JWT signed by APP account key via KMS
	log.Println("Step 3: Creating NACK user JWT (signed by APP account via KMS)...")
	nackClaims := createNackUserClaims(nackKey.PublicKey, appAccountKey.PublicKey)
	appAccountKP := &dummyKeyPair{pubKey: appAccountKey.PublicKey}
	appAccountSigner := createKMSSigner(ctx, client, appAccountKey.KeyID)

	nackJWT, err := nackClaims.EncodeWithSigner(appAccountKP, appAccountSigner)
	if err != nil {
		log.Fatalf("Failed to encode NACK user JWT: %v", err)
	}
	log.Println("  NACK user JWT created successfully")
	log.Println()

	// Step 4: Write credentials file
	log.Println("Step 4: Writing NACK credentials file...")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	credsContent := formatCredentials(nackJWT, nackKey.Seed)
	credsPath := outputDir + "/nack.creds"
	if err := os.WriteFile(credsPath, []byte(credsContent), 0600); err != nil {
		log.Fatalf("Failed to write NACK credentials: %v", err)
	}
	log.Printf("  NACK credentials written to: %s", credsPath)
	log.Println()

	log.Println("Credential generation complete!")
	log.Println()
	log.Println("Generated files:")
	log.Printf("  - %s/nack.creds   (NACK JetStream controller credentials)", outputDir)
}
