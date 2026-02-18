// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// runGenerate orchestrates the config generation process
func runGenerate(ctx context.Context, operatorName, sysAccountName, authAccountName, region, outputDir, aliasPrefix string) {
	client := setupAWSClient(ctx, region)

	log.Println("Generating NATS AWS configuration...")
	log.Println()

	// Setup KMS keys for Operator and SYS
	operatorKey, sysKey := setupKMSKeys(ctx, client, aliasPrefix)

	// Generate local keys for AUTH and Sentinel
	authKey, sentinelKey := setupLocalKeys()

	// Create all JWTs
	operatorJWT, sysAccountJWT, authAccountJWT, sentinelUserJWT := createAllJWTs(
		ctx, client, operatorKey, sysKey, authKey, sentinelKey,
		operatorName, sysAccountName, authAccountName,
	)

	// Write configuration files
	writeConfigFiles(outputDir, operatorJWT, sysAccountJWT, authAccountJWT, sentinelUserJWT, sysKey.PublicKey, authKey.PublicKey)

	log.Println()
	log.Println("Configuration generation complete!")
	log.Println()
	log.Println("Generated files:")
	log.Printf("  - %s/nats-server.conf   (NATS server configuration)", outputDir)
}

func setupAWSClient(ctx context.Context, region string) *kms.Client {
	cfg, err := loadAWSConfig(ctx, region)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}
	return kms.NewFromConfig(cfg)
}

func setupKMSKeys(ctx context.Context, client *kms.Client, aliasPrefix string) (*KMSKey, *KMSKey) {
	// Get or create Operator key pair in KMS
	log.Println("Step 1: Getting/creating Operator key pair in KMS...")
	operatorKey, operatorExisted, err := getOrCreateKMSKey(ctx, client, nkeys.PrefixByteOperator, aliasPrefix+"-operator")
	if err != nil {
		log.Fatalf("Failed to get/create operator key: %v", err)
	}
	logKeyStatus("Operator", operatorKey, operatorExisted)

	// Get or create SYS Account key pair in KMS
	log.Println("Step 2: Getting/creating SYS Account key pair in KMS...")
	sysKey, sysExisted, err := getOrCreateKMSKey(ctx, client, nkeys.PrefixByteAccount, aliasPrefix+"-sys-account")
	if err != nil {
		log.Fatalf("Failed to get/create SYS account key: %v", err)
	}
	logKeyStatus("SYS Account", sysKey, sysExisted)

	return operatorKey, sysKey
}

func setupLocalKeys() (*LocalKey, *LocalKey) {
	// Generate AUTH Account key pair locally
	log.Println("Step 3: Generating AUTH Account key pair (local)...")
	authKey, err := createLocalKey(nkeys.PrefixByteAccount)
	if err != nil {
		log.Fatalf("Failed to create AUTH account key: %v", err)
	}
	log.Printf("  AUTH Account Public Key: %s", authKey.PublicKey)
	log.Println()

	// Generate Sentinel User key pair locally
	log.Println("Step 4: Generating Sentinel User key pair (local)...")
	sentinelKey, err := createLocalKey(nkeys.PrefixByteUser)
	if err != nil {
		log.Fatalf("Failed to create sentinel user key: %v", err)
	}
	log.Printf("  Sentinel User Public Key: %s", sentinelKey.PublicKey)
	log.Println()

	return authKey, sentinelKey
}

func createAllJWTs(
	ctx context.Context, client *kms.Client,
	operatorKey, sysKey *KMSKey, authKey, sentinelKey *LocalKey,
	operatorName, sysAccountName, authAccountName string,
) (string, string, string, string) {
	operatorSigner := createKMSSigner(ctx, client, operatorKey.KeyID)

	// Create Operator JWT (self-signed via KMS)
	log.Println("Step 5: Creating Operator JWT...")
	operatorJWT, err := createOperatorJWT(operatorKey.PublicKey, operatorName, sysKey.PublicKey, operatorSigner)
	if err != nil {
		log.Fatalf("Failed to create operator JWT: %v", err)
	}
	log.Println("  Operator JWT created successfully")
	log.Println()

	// Create SYS Account JWT (signed by operator via KMS)
	log.Println("Step 6: Creating SYS Account JWT (signed by operator)...")
	sysAccountJWT, err := createAccountJWT(sysKey.PublicKey, sysAccountName, operatorKey.PublicKey, operatorSigner)
	if err != nil {
		log.Fatalf("Failed to create SYS account JWT: %v", err)
	}
	log.Println("  SYS Account JWT created successfully")
	log.Println()

	// Create AUTH Account JWT (signed by operator via KMS)
	log.Println("Step 7: Creating AUTH Account JWT (signed by operator)...")
	authAccountJWT, err := createAccountJWT(authKey.PublicKey, authAccountName, operatorKey.PublicKey, operatorSigner)
	if err != nil {
		log.Fatalf("Failed to create AUTH account JWT: %v", err)
	}
	log.Println("  AUTH Account JWT created successfully")
	log.Println()

	// Create Sentinel User JWT (signed by AUTH account locally, bearer token)
	log.Println("Step 8: Creating Sentinel User JWT (bearer token)...")
	sentinelUserJWT, err := createSentinelUserJWTForGenerate(sentinelKey.PublicKey, authKey.KeyPair)
	if err != nil {
		log.Fatalf("Failed to create sentinel user JWT: %v", err)
	}
	log.Println("  Sentinel User JWT created successfully")
	log.Println()

	return operatorJWT, sysAccountJWT, authAccountJWT, sentinelUserJWT
}

func writeConfigFiles(outputDir, operatorJWT, sysAccountJWT, authAccountJWT, sentinelUserJWT, sysAccountPubKey, authAccountPubKey string) {
	log.Println("Step 9: Generating NATS server configuration...")

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	serverConfig := generateServerConfig(operatorJWT, sysAccountJWT, authAccountJWT, sentinelUserJWT, sysAccountPubKey, authAccountPubKey)
	configPath := outputDir + "/nats-server.conf"
	if err := os.WriteFile(configPath, []byte(serverConfig), 0644); err != nil {
		log.Fatalf("Failed to write server config: %v", err)
	}
	log.Printf("  Server config written to: %s", configPath)
}

func logKeyStatus(keyType string, key *KMSKey, existed bool) {
	if existed {
		log.Printf("  Using existing %s key", keyType)
	} else {
		log.Printf("  Created new %s key", keyType)
	}
	log.Printf("  %s Public Key: %s", keyType, key.PublicKey)
	log.Printf("  KMS Key ID: %s", key.KeyID)
	log.Println()
}

func createOperatorJWT(operatorPubKey, operatorName, systemAccount string, signer jwt.SignFn) (string, error) {
	claims := jwt.NewOperatorClaims(operatorPubKey)
	claims.Name = operatorName
	claims.SystemAccount = systemAccount
	claims.IssuedAt = time.Now().Unix()

	kp := &dummyKeyPair{pubKey: operatorPubKey}

	token, err := claims.EncodeWithSigner(kp, signer)
	if err != nil {
		return "", fmt.Errorf("failed to encode operator JWT: %w", err)
	}

	return token, nil
}

func createAccountJWT(accountPubKey, accountName, issuerPubKey string, signer jwt.SignFn) (string, error) {
	claims := jwt.NewAccountClaims(accountPubKey)
	claims.Name = accountName
	claims.IssuedAt = time.Now().Unix()

	// Set unlimited limits
	claims.Limits.Conn = -1
	claims.Limits.LeafNodeConn = -1
	claims.Limits.Subs = -1
	claims.Limits.Data = -1
	claims.Limits.Payload = -1
	claims.Limits.Imports = -1
	claims.Limits.Exports = -1
	claims.Limits.WildcardExports = true

	kp := &dummyKeyPair{pubKey: issuerPubKey}

	token, err := claims.EncodeWithSigner(kp, signer)
	if err != nil {
		return "", fmt.Errorf("failed to encode account JWT: %w", err)
	}

	return token, nil
}

func createSentinelUserJWTForGenerate(userPubKey string, issuerKeyPair nkeys.KeyPair) (string, error) {
	claims := jwt.NewUserClaims(userPubKey)
	claims.Name = "sentinel"
	claims.IssuedAt = time.Now().Unix()

	// Enable bearer token - allows connection without nonce signing
	claims.BearerToken = true

	// No permissions - sentinel user has no access
	claims.Pub.Deny.Add(">")
	claims.Sub.Deny.Add(">")

	token, err := claims.Encode(issuerKeyPair)
	if err != nil {
		return "", fmt.Errorf("failed to encode user JWT: %w", err)
	}

	return token, nil
}

func generateServerConfig(operatorJWT, sysAccountJWT, authAccountJWT, sentinelUserJWT, sysAccountPubKey, authAccountPubKey string) string {
	return fmt.Sprintf(`# NATS Server Configuration
# Generated by nats-aws-auth
# Operator and SYS Account keys are stored in AWS KMS

# Operator configuration (embedded JWT)
operator: %s

# System account
system_account: %s

# Default sentinel user (for auth callout)
default_sentinel: %s

# Full resolver configuration
resolver: {
    type: full
    dir: './jwt'
    allow_delete: true
    interval: "2m"
    limit: 1000
}

# Resolver preload for accounts (loaded at startup)
resolver_preload: {
    # SYS Account
    %s: %s
    # AUTH Account
    %s: %s
}

# Server settings
port: 4222
http_port: 8222

# JetStream configuration
jetstream: {
    store_dir: "./jetstream"
    max_mem: 1G
    max_file: 10G
}

# Logging
debug: false
trace: false
logtime: true
`,
		operatorJWT,
		sysAccountPubKey,
		sentinelUserJWT,
		sysAccountPubKey, sysAccountJWT,
		authAccountPubKey, authAccountJWT)
}