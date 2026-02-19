// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"go.uber.org/zap"
)

// runGenerate orchestrates the config generation process
func runGenerate(ctx context.Context, logger *zap.Logger, operatorName, sysAccountName, authAccountName, region, outputDir, aliasPrefix string) {
	client := setupAWSClient(ctx, logger, region)

	logger.Info("Generating NATS AWS configuration...")

	// Setup KMS keys for Operator and SYS
	operatorKey, sysKey := setupKMSKeys(ctx, logger, client, aliasPrefix)

	// Generate local keys for AUTH and Sentinel
	authKey, sentinelKey := setupLocalKeys(logger)

	// Create all JWTs
	operatorJWT, sysAccountJWT, authAccountJWT, sentinelUserJWT := createAllJWTs(
		ctx, logger, client, operatorKey, sysKey, authKey, sentinelKey,
		operatorName, sysAccountName, authAccountName,
	)

	// Write configuration files
	writeConfigFiles(logger, outputDir, operatorJWT, sysAccountJWT, authAccountJWT, sentinelUserJWT, sysKey.PublicKey, authKey.PublicKey)

	logger.Info("Configuration generation complete!")
	logger.Info("Generated files",
		zap.String("config", fmt.Sprintf("%s/nats-server.conf", outputDir)))
}

func setupAWSClient(ctx context.Context, logger *zap.Logger, region string) *kms.Client {
	cfg, err := loadAWSConfig(ctx, region)
	if err != nil {
		logger.Fatal("Failed to load AWS config", zap.Error(err))
	}
	return kms.NewFromConfig(cfg)
}

func setupKMSKeys(ctx context.Context, logger *zap.Logger, client *kms.Client, aliasPrefix string) (*KMSKey, *KMSKey) {
	// Get or create Operator key pair in KMS
	logger.Info("Getting/creating Operator key pair in KMS...")
	operatorKey, operatorExisted, err := getOrCreateKMSKey(ctx, client, nkeys.PrefixByteOperator, aliasPrefix+"-operator")
	if err != nil {
		logger.Fatal("Failed to get/create operator key", zap.Error(err))
	}
	logKeyStatus(logger, "Operator", operatorKey, operatorExisted)

	// Get or create SYS Account key pair in KMS
	logger.Info("Getting/creating SYS Account key pair in KMS...")
	sysKey, sysExisted, err := getOrCreateKMSKey(ctx, client, nkeys.PrefixByteAccount, aliasPrefix+"-sys-account")
	if err != nil {
		logger.Fatal("Failed to get/create SYS account key", zap.Error(err))
	}
	logKeyStatus(logger, "SYS Account", sysKey, sysExisted)

	return operatorKey, sysKey
}

func setupLocalKeys(logger *zap.Logger) (*LocalKey, *LocalKey) {
	// Generate AUTH Account key pair locally
	logger.Info("Generating AUTH Account key pair (local)...")
	authKey, err := createLocalKey(nkeys.PrefixByteAccount)
	if err != nil {
		logger.Fatal("Failed to create AUTH account key", zap.Error(err))
	}
	logger.Debug("AUTH Account Public Key", zap.String("public_key", authKey.PublicKey))

	// Generate Sentinel User key pair locally
	logger.Info("Generating Sentinel User key pair (local)...")
	sentinelKey, err := createLocalKey(nkeys.PrefixByteUser)
	if err != nil {
		logger.Fatal("Failed to create sentinel user key", zap.Error(err))
	}
	logger.Debug("Sentinel User Public Key", zap.String("public_key", sentinelKey.PublicKey))

	return authKey, sentinelKey
}

func createAllJWTs(
	ctx context.Context, logger *zap.Logger, client *kms.Client,
	operatorKey, sysKey *KMSKey, authKey, sentinelKey *LocalKey,
	operatorName, sysAccountName, authAccountName string,
) (string, string, string, string) {
	operatorSigner := createKMSSigner(ctx, client, operatorKey.KeyID)

	// Create Operator JWT (self-signed via KMS)
	logger.Info("Creating Operator JWT...")
	operatorJWT, err := createOperatorJWT(operatorKey.PublicKey, operatorName, sysKey.PublicKey, operatorSigner)
	if err != nil {
		logger.Fatal("Failed to create operator JWT", zap.Error(err))
	}
	logger.Debug("Operator JWT created successfully")

	// Create SYS Account JWT (signed by operator via KMS)
	logger.Info("Creating SYS Account JWT (signed by operator)...")
	sysAccountJWT, err := createAccountJWT(sysKey.PublicKey, sysAccountName, operatorKey.PublicKey, operatorSigner)
	if err != nil {
		logger.Fatal("Failed to create SYS account JWT", zap.Error(err))
	}
	logger.Debug("SYS Account JWT created successfully")

	// Create AUTH Account JWT (signed by operator via KMS)
	logger.Info("Creating AUTH Account JWT (signed by operator)...")
	authAccountJWT, err := createAccountJWT(authKey.PublicKey, authAccountName, operatorKey.PublicKey, operatorSigner)
	if err != nil {
		logger.Fatal("Failed to create AUTH account JWT", zap.Error(err))
	}
	logger.Debug("AUTH Account JWT created successfully")

	// Create Sentinel User JWT (signed by AUTH account locally, bearer token)
	logger.Info("Creating Sentinel User JWT (bearer token)...")
	sentinelUserJWT, err := createSentinelUserJWTForGenerate(sentinelKey.PublicKey, authKey.KeyPair)
	if err != nil {
		logger.Fatal("Failed to create sentinel user JWT", zap.Error(err))
	}
	logger.Debug("Sentinel User JWT created successfully")

	return operatorJWT, sysAccountJWT, authAccountJWT, sentinelUserJWT
}

func writeConfigFiles(logger *zap.Logger, outputDir, operatorJWT, sysAccountJWT, authAccountJWT, sentinelUserJWT, sysAccountPubKey, authAccountPubKey string) {
	logger.Info("Generating NATS server configuration...")

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logger.Fatal("Failed to create output directory", zap.Error(err))
	}

	serverConfig := generateServerConfig(operatorJWT, sysAccountJWT, authAccountJWT, sentinelUserJWT, sysAccountPubKey, authAccountPubKey)
	configPath := outputDir + "/nats-server.conf"
	if err := os.WriteFile(configPath, []byte(serverConfig), 0644); err != nil {
		logger.Fatal("Failed to write server config", zap.Error(err))
	}
	logger.Debug("Server config written", zap.String("path", configPath))
}

func logKeyStatus(logger *zap.Logger, keyType string, key *KMSKey, existed bool) {
	if existed {
		logger.Debug("Using existing key", zap.String("type", keyType))
	} else {
		logger.Debug("Created new key", zap.String("type", keyType))
	}
	logger.Debug("Key details",
		zap.String("type", keyType),
		zap.String("public_key", key.PublicKey),
		zap.String("kms_key_id", key.KeyID))
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
