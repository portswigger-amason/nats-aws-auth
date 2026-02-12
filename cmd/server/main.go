// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-kms-auth contributors

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/portswigger/nats-kms-auth/internal/auth"
	jwtvalidator "github.com/portswigger/nats-kms-auth/internal/jwt"
	"github.com/portswigger/nats-kms-auth/internal/k8s"
	flag "github.com/spf13/pflag"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// AuthCalloutHandler handles NATS auth callout requests
type AuthCalloutHandler struct {
	signingKP      nkeys.KeyPair
	authAccountPub string
	targetAccount  string
	authorizer     auth.Authorizer
}

// ==========================================
// Main Entry Point
// ==========================================

func main() {
	// Common flags
	var generate = flag.Bool("generate", false, "Generate a config file for nats-server to stdout and exit")
	var region = flag.String("region", "", "AWS region (uses AWS config/environment if not specified)")

	// Config generation mode flags
	var operatorName = flag.String("operator-name", "KMS-Operator", "operator name for generated configuration")
	var sysAccountName = flag.String("sys-account", "SYS", "system account name")
	var outputDir = flag.String("output", ".", "output directory for generated files")
	var aliasPrefix = flag.String("alias-prefix", "nats", "prefix for KMS key aliases")

	// Auth service mode flags
	var authAccountName = flag.String("auth-account-name", "AUTH", "name of the AUTH account")
	var appAccountName = flag.String("app-account-name", "APP", "name of the APP account for authorized users")
	var natsURL = flag.String("url", "localhost:4222", "NATS server URL")

	// Auth backend flags
	var authBackend = flag.String("auth-backend", "allow-all", "auth backend: 'k8s-oidc' or 'allow-all'")
	var jwksURL = flag.String("jwks-url", "https://kubernetes.default.svc/openid/v1/jwks", "JWKS endpoint URL for k8s-oidc backend")
	var jwksPath = flag.String("jwks-path", "", "JWKS file path (for testing, mutually exclusive with --jwks-url)")
	var jwtIssuer = flag.String("jwt-issuer", "", "expected JWT issuer for k8s-oidc backend")
	var jwtAudience = flag.String("jwt-audience", "nats", "expected JWT audience for k8s-oidc backend")

	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	// Customize usage to add context around the auto-generated flags
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "This is a service that implements the callout authentication mechanism for NATS.\n")
		fmt.Fprintf(os.Stderr, "Please see the README for more information: https://github.com/portswigger/nats-kms-auth\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	ctx := context.Background()

	if *generate {
		runGenerate(ctx, *operatorName, *sysAccountName, *authAccountName, *region, *outputDir, *aliasPrefix)
	} else {
		authorizer := initAuthorizer(ctx, *authBackend, *jwksURL, *jwksPath, *jwtIssuer, *jwtAudience)
		runAuthService(ctx, *authAccountName, *appAccountName, *region, *natsURL, authorizer)
	}
}

// ==========================================
// Config Generation Mode Functions
// ==========================================

func runGenerate(ctx context.Context, operatorName, sysAccountName, authAccountName, region, outputDir, aliasPrefix string) {
	// Load AWS configuration
	cfg, err := loadAWSConfig(ctx, region)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	client := kms.NewFromConfig(cfg)

	log.Println("Generating NATS KMS configuration...")
	log.Println()

	// Step 1: Get or create Operator key pair in KMS
	log.Println("Step 1: Getting/creating Operator key pair in KMS...")
	operatorKey, operatorExisted, err := getOrCreateKMSKey(ctx, client, nkeys.PrefixByteOperator, aliasPrefix+"-operator")
	if err != nil {
		log.Fatalf("Failed to get/create operator key: %v", err)
	}
	if operatorExisted {
		log.Printf("  Using existing Operator key")
	} else {
		log.Printf("  Created new Operator key")
	}
	log.Printf("  Operator Public Key: %s", operatorKey.PublicKey)
	log.Printf("  KMS Key ID: %s", operatorKey.KeyID)
	log.Println()

	// Step 2: Get or create SYS Account key pair in KMS
	log.Println("Step 2: Getting/creating SYS Account key pair in KMS...")
	sysKey, sysExisted, err := getOrCreateKMSKey(ctx, client, nkeys.PrefixByteAccount, aliasPrefix+"-sys-account")
	if err != nil {
		log.Fatalf("Failed to get/create SYS account key: %v", err)
	}
	if sysExisted {
		log.Printf("  Using existing SYS Account key")
	} else {
		log.Printf("  Created new SYS Account key")
	}
	log.Printf("  SYS Account Public Key: %s", sysKey.PublicKey)
	log.Printf("  KMS Key ID: %s", sysKey.KeyID)
	log.Println()

	// Step 3: Generate AUTH Account key pair locally
	log.Println("Step 3: Generating AUTH Account key pair (local)...")
	authKey, err := createLocalKey(nkeys.PrefixByteAccount)
	if err != nil {
		log.Fatalf("Failed to create AUTH account key: %v", err)
	}
	log.Printf("  AUTH Account Public Key: %s", authKey.PublicKey)
	log.Println()

	// Step 4: Generate Sentinel User key pair locally
	log.Println("Step 4: Generating Sentinel User key pair (local)...")
	sentinelKey, err := createLocalKey(nkeys.PrefixByteUser)
	if err != nil {
		log.Fatalf("Failed to create sentinel user key: %v", err)
	}
	log.Printf("  Sentinel User Public Key: %s", sentinelKey.PublicKey)
	log.Println()

	// Create KMS signer function for operator
	operatorSigner := createKMSSigner(ctx, client, operatorKey.KeyID)

	// Step 5: Create Operator JWT (self-signed via KMS)
	log.Println("Step 5: Creating Operator JWT...")
	operatorJWT, err := createOperatorJWT(operatorKey.PublicKey, operatorName, sysKey.PublicKey, operatorSigner)
	if err != nil {
		log.Fatalf("Failed to create operator JWT: %v", err)
	}
	log.Println("  Operator JWT created successfully")
	log.Println()

	// Step 6: Create SYS Account JWT (signed by operator via KMS)
	log.Println("Step 6: Creating SYS Account JWT (signed by operator)...")
	sysAccountJWT, err := createAccountJWT(sysKey.PublicKey, sysAccountName, operatorKey.PublicKey, operatorSigner)
	if err != nil {
		log.Fatalf("Failed to create SYS account JWT: %v", err)
	}
	log.Println("  SYS Account JWT created successfully")
	log.Println()

	// Step 7: Create AUTH Account JWT (signed by operator via KMS)
	log.Println("Step 7: Creating AUTH Account JWT (signed by operator)...")
	authAccountJWT, err := createAccountJWT(authKey.PublicKey, authAccountName, operatorKey.PublicKey, operatorSigner)
	if err != nil {
		log.Fatalf("Failed to create AUTH account JWT: %v", err)
	}
	log.Println("  AUTH Account JWT created successfully")
	log.Println()

	// Step 8: Create Sentinel User JWT (signed by AUTH account locally, bearer token)
	log.Println("Step 8: Creating Sentinel User JWT (bearer token)...")
	sentinelUserJWT, err := createSentinelUserJWTForGenerate(sentinelKey.PublicKey, authKey.KeyPair)
	if err != nil {
		log.Fatalf("Failed to create sentinel user JWT: %v", err)
	}
	log.Println("  Sentinel User JWT created successfully")
	log.Println()

	// Step 9: Generate NATS server configuration
	log.Println("Step 9: Generating NATS server configuration...")

	// Write output files
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Write server config
	serverConfig := generateServerConfig(operatorJWT, sysAccountJWT, authAccountJWT, sentinelUserJWT, sysKey.PublicKey, authKey.PublicKey)
	configPath := outputDir + "/nats-server.conf"
	if err := os.WriteFile(configPath, []byte(serverConfig), 0644); err != nil {
		log.Fatalf("Failed to write server config: %v", err)
	}
	log.Printf("  Server config written to: %s", configPath)

	log.Println()
	log.Println("Configuration generation complete!")
	log.Println()
	log.Println("Generated files:")
	log.Printf("  - %s/nats-server.conf   (NATS server configuration)", outputDir)
}

func createOperatorJWT(operatorPubKey, operatorName, systemAccount string, signer jwt.SignFn) (string, error) {
	claims := jwt.NewOperatorClaims(operatorPubKey)
	claims.Name = operatorName
	claims.Operator.SystemAccount = systemAccount
	claims.IssuedAt = time.Now().Unix()

	// Create a dummy keypair for the issuer validation
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
	claims.Account.Limits.Conn = -1
	claims.Account.Limits.LeafNodeConn = -1
	claims.Account.Limits.Subs = -1
	claims.Account.Limits.Data = -1
	claims.Account.Limits.Payload = -1
	claims.Account.Limits.Imports = -1
	claims.Account.Limits.Exports = -1
	claims.Account.Limits.WildcardExports = true

	// Create a dummy keypair for the issuer
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
	claims.User.BearerToken = true

	// No permissions - sentinel user has no access
	claims.User.Permissions.Pub.Deny.Add(">")
	claims.User.Permissions.Sub.Deny.Add(">")

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
    allow_delete: false
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

// ==========================================
// Auth Service Mode Functions
// ==========================================

func runAuthService(ctx context.Context, authAccountName, appAccountName, region, natsURL string, authorizer auth.Authorizer) {

	log.Println("NATS Client with KMS-signed credentials")
	log.Println()

	// Step 1: Load AWS configuration
	log.Println("Step 1: Loading AWS configuration...")
	cfg, err := loadAWSConfig(ctx, region)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}
	client := kms.NewFromConfig(cfg)
	log.Println("  AWS config loaded successfully")
	log.Println()

	// Step 2: Look up Operator key from KMS
	log.Println("Step 2: Looking up Operator key from KMS (alias: nats-operator)...")
	operatorKey, err := getExistingKMSKey(ctx, client, "alias/nats-operator", nkeys.PrefixByteOperator)
	if err != nil {
		log.Fatalf("Failed to find Operator key in KMS: %v\n\nPlease run with -generate first to create the KMS keys.", err)
	}
	operatorKMSKeyID := operatorKey.KeyID
	operatorPublicKey := operatorKey.PublicKey
	log.Printf("  Operator Public Key: %s", operatorPublicKey)
	log.Printf("  KMS Key ID: %s", operatorKMSKeyID)
	log.Println()

	// Step 3: Look up SYS Account key from KMS
	log.Println("Step 3: Looking up SYS Account key from KMS (alias: nats-sys-account)...")
	sysKey, err := getExistingKMSKey(ctx, client, "alias/nats-sys-account", nkeys.PrefixByteAccount)
	if err != nil {
		log.Fatalf("Failed to find SYS Account key in KMS: %v\n\nPlease run with -generate first to create the KMS keys.", err)
	}
	sysKMSKeyID := sysKey.KeyID
	sysAccountPublicKey := sysKey.PublicKey
	log.Printf("  SYS Account Public Key: %s", sysAccountPublicKey)
	log.Printf("  KMS Key ID: %s", sysKMSKeyID)
	log.Println()

	// Step 4: Generate in-memory user keypair
	log.Println("Step 4: Generating in-memory user keypair...")
	userKP, err := nkeys.CreateUser()
	if err != nil {
		log.Fatalf("Failed to create user keypair: %v", err)
	}
	userPubKey, err := userKP.PublicKey()
	if err != nil {
		log.Fatalf("Failed to get user public key: %v", err)
	}
	log.Printf("  User public key: %s", userPubKey)
	log.Println()

	// Step 5: Create user JWT signed by SYS account (via KMS)
	log.Println("Step 5: Creating user JWT signed by SYS account (via KMS)...")
	signer := createKMSSigner(ctx, client, sysKMSKeyID)
	userJWT, err := createUserJWT(userPubKey, sysAccountPublicKey, signer)
	if err != nil {
		log.Fatalf("Failed to create user JWT: %v", err)
	}
	log.Println("  User JWT created successfully")
	log.Println()

	// Step 6: Connect to NATS
	log.Printf("Step 6: Connecting to NATS at %s...", natsURL)
	nc, err := nats.Connect(natsURL, nats.UserJWT(
		func() (string, error) {
			return userJWT, nil
		},
		func(nonce []byte) ([]byte, error) {
			return userKP.Sign(nonce)
		},
	))
	if err != nil {
		log.Fatalf("Failed to connect to NATS: %v", err)
	}
	defer nc.Close()

	log.Println("  Successfully connected to NATS!")
	log.Println()

	// Step 7: Test the connection
	log.Println("Step 7: Testing connection...")

	// Subscribe to a test subject
	sub, err := nc.SubscribeSync("test.subject")
	if err != nil {
		log.Fatalf("Failed to subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	// Publish a test message
	testMsg := []byte("Hello from KMS-signed NATS client!")
	if err := nc.Publish("test.subject", testMsg); err != nil {
		log.Fatalf("Failed to publish: %v", err)
	}
	log.Println("  Published test message")

	// Receive the message
	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		log.Fatalf("Failed to receive message: %v", err)
	}
	log.Printf("  Received message: %s", string(msg.Data))
	log.Println()

	log.Println("Success! Connection and messaging work correctly.")
	log.Println()

	// Step 7: Generate signing keypair for AUTH account
	log.Println("Step 7: Generating in-memory signing keypair for AUTH account...")
	signingKP, err := nkeys.CreateAccount()
	if err != nil {
		log.Fatalf("Failed to create signing keypair: %v", err)
	}
	signingPubKey, err := signingKP.PublicKey()
	if err != nil {
		log.Fatalf("Failed to get signing public key: %v", err)
	}
	log.Printf("  Signing key public key: %s", signingPubKey)
	log.Println()

	// Step 10: Fetch all account JWTs from NATS server using CLAIMS.PACK
	log.Println("Step 8: Fetching all account JWTs from NATS server...")
	log.Println("  Using $SYS.REQ.CLAIMS.PACK to pull all accounts")

	// Create an inbox for responses
	inbox := nats.NewInbox()
	log.Printf("  Response inbox: %s", inbox)

	// Subscribe to the inbox
	claimsSub, err := nc.SubscribeSync(inbox)
	if err != nil {
		log.Fatalf("Failed to subscribe to inbox: %v", err)
	}
	defer claimsSub.Unsubscribe()

	// Request all claims
	if err := nc.PublishRequest("$SYS.REQ.CLAIMS.PACK", inbox, nil); err != nil {
		log.Fatalf("Failed to request claims pack: %v", err)
	}
	log.Println("  Request sent, waiting for responses...")
	log.Println()

	// Collect all responses
	var authJWT string
	var appJWT string
	accountCount := 0

	for {
		resp, err := claimsSub.NextMsg(2 * time.Second)
		if err != nil {
			log.Printf("  Timeout or error waiting for response: %v", err)
			break
		}

		msg := string(resp.Data)
		if msg == "" {
			log.Println("  Received empty response (end of stream)")
			break
		}

		// Response format is "pubkey|jwt"
		parts := strings.Split(msg, "|")
		if len(parts) != 2 {
			log.Printf("  WARNING: Unexpected response format: %s", msg)
			continue
		}

		pubkey := parts[0]
		jwtToken := parts[1]
		accountCount++

		log.Printf("  Account %d: %s", accountCount, pubkey)

		// Try to decode the JWT
		if claims, err := jwt.DecodeAccountClaims(jwtToken); err == nil {
			log.Printf("    Name: %s", claims.Name)
			log.Printf("    Subject: %s", claims.Subject)
			log.Printf("    Issued At: %s", time.Unix(claims.IssuedAt, 0).Format(time.RFC3339))
			if len(claims.Account.SigningKeys) > 0 {
				log.Printf("    Signing Keys: %v", claims.Account.SigningKeys.Keys())
			}

			// Check if this is the AUTH account (match by name)
			if claims.Name == authAccountName {
				log.Println("    ** This is the AUTH account **")
				authJWT = jwtToken
			}

			// Check if this is the APP account (match by name)
			if claims.Name == appAccountName {
				log.Println("    ** This is the APP account **")
				appJWT = jwtToken
			}
		} else {
			log.Printf("    Failed to decode: %v", err)
		}
		log.Println()
	}

	log.Printf("Total accounts received: %d", accountCount)
	log.Println()

	if authJWT == "" {
		log.Fatalf("AUTH account JWT not found in response")
	}

	// Create operator signer (used for signing account JWTs via KMS)
	operatorSigner := createKMSSigner(ctx, client, operatorKMSKeyID)
	operatorKP := &dummyKeyPair{pubKey: operatorPublicKey}
	updateSubject := "$SYS.REQ.CLAIMS.UPDATE"

	// Create APP account if it doesn't exist
	var appClaims *jwt.AccountClaims
	if appJWT == "" {
		log.Println("APP account not found, creating new APP account...")

		// Generate new account keypair for APP
		appKP, err := nkeys.CreateAccount()
		if err != nil {
			log.Fatalf("Failed to create APP account keypair: %v", err)
		}
		appPubKey, err := appKP.PublicKey()
		if err != nil {
			log.Fatalf("Failed to get APP account public key: %v", err)
		}
		log.Printf("  APP account public key: %s", appPubKey)

		// Create APP account claims
		appClaims = jwt.NewAccountClaims(appPubKey)
		appClaims.Name = appAccountName
		appClaims.IssuedAt = time.Now().Unix()

		appJWT, err = appClaims.EncodeWithSigner(operatorKP, operatorSigner)
		if err != nil {
			log.Fatalf("Failed to encode APP account JWT: %v", err)
		}
		log.Println("  APP account JWT created")

		// Publish APP account JWT to NATS
		updateResp, err := nc.Request(updateSubject, []byte(appJWT), 5*time.Second)
		if err != nil {
			log.Fatalf("Failed to publish APP account JWT: %v", err)
		}
		log.Printf("  Response from server: %s", string(updateResp.Data))
		log.Println()
	} else {
		var err error
		appClaims, err = jwt.DecodeAccountClaims(appJWT)
		if err != nil {
			log.Fatalf("Failed to decode APP account JWT: %v", err)
		}
	}

	// Decode the AUTH account JWT
	authClaims, err := jwt.DecodeAccountClaims(authJWT)
	if err != nil {
		log.Fatalf("Failed to decode AUTH account JWT: %v", err)
	}
	log.Printf("Found AUTH account: %s (public key: %s)", authClaims.Name, authClaims.Subject)
	log.Println()

	// Step 11: Create auth user keypair (needed before configuring external authorization)
	log.Println("Step 9: Creating auth user keypair...")
	authUserKP, err := nkeys.CreateUser()
	if err != nil {
		log.Fatalf("Failed to create auth user keypair: %v", err)
	}
	authUserPubKey, err := authUserKP.PublicKey()
	if err != nil {
		log.Fatalf("Failed to get auth user public key: %v", err)
	}
	log.Printf("  Auth user public key: %s", authUserPubKey)
	log.Println()

	// Step 10: Update AUTH account with signing key and external authorization
	log.Println("Step 10: Configuring AUTH account...")

	// Add signing key
	if authClaims.Account.SigningKeys == nil {
		authClaims.Account.SigningKeys = make(jwt.SigningKeys)
	}
	authClaims.Account.SigningKeys.Add(signingPubKey)
	log.Printf("  Added signing key: %s", signingPubKey)

	// Configure external authorization (auth callout)
	// - AuthUsers: users that bypass the callout (the auth service itself)
	// - AllowedAccounts: accounts the auth service can issue users for ("*" = any)
	authClaims.Account.Authorization = jwt.ExternalAuthorization{
		AuthUsers:       []string{authUserPubKey},
		AllowedAccounts: []string{"*"},
	}
	log.Printf("  Enabled external authorization")
	log.Printf("  Auth user (bypasses callout): %s", authUserPubKey)

	authClaims.IssuedAt = time.Now().Unix()
	log.Println()

	// Step 11: Re-sign AUTH account JWT with Operator (via KMS)
	log.Println("Step 11: Re-signing AUTH account JWT with Operator (via KMS)...")

	updatedAuthJWT, err := authClaims.EncodeWithSigner(operatorKP, operatorSigner)
	if err != nil {
		log.Fatalf("Failed to encode updated AUTH account JWT: %v", err)
	}
	log.Println("  AUTH account JWT re-signed successfully")
	log.Println()

	// Step 12: Publish updated AUTH account JWT to NATS
	log.Println("Step 12: Publishing updated AUTH account JWT to NATS...")

	updateResp, err := nc.Request(updateSubject, []byte(updatedAuthJWT), 5*time.Second)
	if err != nil {
		log.Fatalf("Failed to publish updated JWT: %v", err)
	}
	log.Printf("  Response from server: %s", string(updateResp.Data))
	log.Println()

	log.Println("Success! AUTH account configured with:")
	log.Println("  - Signing key for issuing user JWTs")
	log.Println("  - External authorization (auth callout) enabled")
	log.Println()

	// Step 12b: Add signing key and enable JetStream on APP account
	log.Println("Step 13: Configuring APP account (signing key + JetStream)...")
	if appClaims.Account.SigningKeys == nil {
		appClaims.Account.SigningKeys = make(jwt.SigningKeys)
	}
	appClaims.Account.SigningKeys.Add(signingPubKey)
	log.Printf("  Added signing key: %s", signingPubKey)

	// Enable JetStream on APP account with unlimited resources
	appClaims.Account.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage:        -1, // Unlimited
		DiskStorage:          -1, // Unlimited
		Streams:              -1, // Unlimited
		Consumer:             -1, // Unlimited
		MaxAckPending:        -1, // Unlimited
		MemoryMaxStreamBytes: -1, // Unlimited
		DiskMaxStreamBytes:   -1, // Unlimited
		MaxBytesRequired:     false,
	}
	log.Println("  Enabled JetStream with unlimited limits")

	appClaims.IssuedAt = time.Now().Unix()

	// Re-sign APP account JWT with Operator (via KMS)
	updatedAppJWT, err := appClaims.EncodeWithSigner(operatorKP, operatorSigner)
	if err != nil {
		log.Fatalf("Failed to encode updated APP account JWT: %v", err)
	}
	log.Println("  APP account JWT re-signed successfully")

	// Publish updated APP account JWT to NATS
	appUpdateResp, err := nc.Request(updateSubject, []byte(updatedAppJWT), 5*time.Second)
	if err != nil {
		log.Fatalf("Failed to publish updated APP account JWT: %v", err)
	}
	log.Printf("  Response from server: %s", string(appUpdateResp.Data))
	log.Println()

	// Step 13: Create auth user JWT signed by the signing key
	log.Println("Step 14: Creating auth user JWT signed by signing key...")
	log.Printf("  Issuer Account (AUTH): %s", authClaims.Subject)
	log.Printf("  Signing Key (Issuer): %s", signingPubKey)
	authUserJWT, err := createUserJWTWithKey(authUserPubKey, "auth", authClaims.Subject, signingKP)
	if err != nil {
		log.Fatalf("Failed to create auth user JWT: %v", err)
	}
	log.Println("  User JWT created successfully")
	log.Println()

	// Step 17: Create sentinel user (triggers auth callout when connecting)
	log.Println("Step 15: Creating sentinel user for auth callout testing...")
	sentinelKP, err := nkeys.CreateUser()
	if err != nil {
		log.Fatalf("Failed to create sentinel keypair: %v", err)
	}
	sentinelPubKey, err := sentinelKP.PublicKey()
	if err != nil {
		log.Fatalf("Failed to get sentinel public key: %v", err)
	}
	sentinelSeed, err := sentinelKP.Seed()
	if err != nil {
		log.Fatalf("Failed to get sentinel seed: %v", err)
	}
	log.Printf("  Sentinel public key: %s", sentinelPubKey)

	// Create sentinel JWT with denied permissions (triggers callout)
	sentinelJWT, err := createSentinelUserJWTForAuthService(sentinelPubKey, authClaims.Subject, signingKP)
	if err != nil {
		log.Fatalf("Failed to create sentinel JWT: %v", err)
	}

	sentinelCreds := fmt.Sprintf(`-----BEGIN NATS USER JWT-----
%s
------END NATS USER JWT------

-----BEGIN USER NKEY SEED-----
%s
------END USER NKEY SEED------
`, sentinelJWT, string(sentinelSeed))

	// Write sentinel credentials to current directory (persistent)
	if err := os.WriteFile("sentinel.creds", []byte(sentinelCreds), 0600); err != nil {
		log.Fatalf("Failed to write sentinel credentials: %v", err)
	}
	log.Println("  Sentinel credentials written to: sentinel.creds")
	log.Println()

	// Step 17: Connect to NATS as auth user
	log.Printf("Step 17: Connecting to NATS as 'auth' user in AUTH account...")
	authNC, err := nats.Connect(natsURL, nats.UserJWT(
		func() (string, error) {
			return authUserJWT, nil
		},
		func(nonce []byte) ([]byte, error) {
			return authUserKP.Sign(nonce)
		},
	))
	if err != nil {
		log.Fatalf("Failed to connect as auth user: %v", err)
	}
	defer authNC.Close()
	log.Println("  Successfully connected as auth user!")
	log.Println()

	// Step 16: Test messaging with auth user
	log.Println("Step 17: Testing messaging as auth user...")
	testSubject := "auth.test.message"

	// Subscribe
	authSub, err := authNC.SubscribeSync(testSubject)
	if err != nil {
		log.Fatalf("Failed to subscribe as auth user: %v", err)
	}
	defer authSub.Unsubscribe()
	log.Printf("  Subscribed to: %s", testSubject)

	// Publish
	testMessage := []byte("Hello from auth user in AUTH account!")
	if err := authNC.Publish(testSubject, testMessage); err != nil {
		log.Fatalf("Failed to publish as auth user: %v", err)
	}
	log.Println("  Published test message")

	// Receive
	authMsg, err := authSub.NextMsg(2 * time.Second)
	if err != nil {
		log.Fatalf("Failed to receive message as auth user: %v", err)
	}
	log.Printf("  Received message: %s", string(authMsg.Data))
	log.Println()

	log.Println("SUCCESS! Setup completed:")
	log.Println("  ✓ Connected to NATS as SYS user with KMS-signed credentials")
	log.Println("  ✓ Fetched all account JWTs from NATS server")
	log.Println("  ✓ Generated signing key for AUTH and APP accounts")
	log.Println("  ✓ Configured external authorization (auth callout) on AUTH account")
	log.Println("  ✓ Created APP account for authorized users")
	log.Println("  ✓ Created 'auth' user in AUTH account (bypasses callout)")
	log.Println("  ✓ Connected as 'auth' user and verified messaging")
	log.Println()

	// Step 17: Start auth callout handler
	log.Println("Step 18: Starting auth callout handler...")
	authCalloutSubject := "$SYS.REQ.USER.AUTH"

	handler := &AuthCalloutHandler{
		signingKP:      signingKP,
		authAccountPub: authClaims.Subject,
		targetAccount:  appClaims.Subject, // Users are issued for APP account (not AUTH)
		authorizer:     authorizer,
	}
	log.Printf("  Auth callout will issue users for APP account: %s", appClaims.Subject)

	authCalloutSub, err := authNC.Subscribe(authCalloutSubject, handler.HandleAuthRequest)
	if err != nil {
		log.Fatalf("Failed to subscribe to auth callout: %v", err)
	}
	defer authCalloutSub.Unsubscribe()

	log.Printf("  Subscribed to: %s", authCalloutSubject)
	log.Println()

	log.Println("===========================================")
	log.Println("Auth callout service is now running!")
	log.Println("===========================================")
	log.Println()
	log.Println("The service will authorize incoming connections.")
	log.Println("Press Ctrl+C to exit...")
	log.Println()

	// Keep the connection alive
	select {}
}

func createUserJWT(userPubKey, issuerPubKey string, signer jwt.SignFn) (string, error) {
	claims := jwt.NewUserClaims(userPubKey)
	claims.Name = "sys"
	claims.IssuedAt = time.Now().Unix()

	// Allow full permissions for this user
	// (In production, you'd want to restrict this appropriately)

	// Create a dummy keypair for the issuer (SYS account)
	kp := &dummyKeyPair{pubKey: issuerPubKey}

	token, err := claims.EncodeWithSigner(kp, signer)
	if err != nil {
		return "", fmt.Errorf("failed to encode user JWT: %w", err)
	}

	return token, nil
}

func createUserJWTWithKey(userPubKey, userName, accountPubKey string, signingKeyPair nkeys.KeyPair) (string, error) {
	claims := jwt.NewUserClaims(userPubKey)
	claims.Name = userName
	claims.IssuedAt = time.Now().Unix()

	// Set the account that this user belongs to
	// The Issuer will automatically be set to the signing key's public key when we call Encode()
	claims.IssuerAccount = accountPubKey

	// Allow full permissions for this user
	// (In production, you'd want to restrict this appropriately)

	token, err := claims.Encode(signingKeyPair)
	if err != nil {
		return "", fmt.Errorf("failed to encode user JWT: %w", err)
	}

	return token, nil
}

// createSentinelUserJWTForAuthService creates a sentinel user JWT with denied permissions
// This user triggers auth callout when connecting (not in auth_users list)
func createSentinelUserJWTForAuthService(userPubKey, accountPubKey string, signingKeyPair nkeys.KeyPair) (string, error) {
	claims := jwt.NewUserClaims(userPubKey)
	claims.Name = "sentinel"
	claims.IssuedAt = time.Now().Unix()
	claims.IssuerAccount = accountPubKey

	// Deny all pub/sub permissions - this ensures auth callout is triggered
	claims.Permissions = jwt.Permissions{
		Pub: jwt.Permission{
			Deny: []string{">"},
		},
		Sub: jwt.Permission{
			Deny: []string{">"},
		},
	}

	token, err := claims.Encode(signingKeyPair)
	if err != nil {
		return "", fmt.Errorf("failed to encode sentinel JWT: %w", err)
	}

	return token, nil
}

// HandleAuthRequest processes an incoming auth callout request
func (h *AuthCalloutHandler) HandleAuthRequest(msg *nats.Msg) {
	log.Printf("[AUTH] Received auth request")

	// The auth request is a JWT that we need to decode
	authRequestJWT := string(msg.Data)

	// Decode the authorization request claims
	authClaims, err := jwt.DecodeAuthorizationRequestClaims(authRequestJWT)
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to decode auth request: %v", err)
		h.respondWithError(msg, "failed to decode authorization request")
		return
	}

	// Extract request information (AuthorizationRequest is embedded)
	userNKey := authClaims.UserNkey
	clientInfo := authClaims.ClientInformation
	connect := authClaims.ConnectOptions

	log.Printf("[AUTH]   User NKey: %s", userNKey)
	log.Printf("[AUTH]   Client: %s (host: %s)", clientInfo.Name, clientInfo.Host)

	// Determine authentication method and log it
	authMethod := "none"
	if connect.Token != "" {
		authMethod = "bearer_token"
	} else if connect.Username != "" {
		authMethod = "username_password"
	} else if connect.JWT != "" {
		authMethod = "jwt"
	} else if connect.Nkey != "" {
		authMethod = "nkey"
	}
	log.Printf("[AUTH]   Auth method: %s", authMethod)

	// Make authorization decision
	authorized, userName, permissions := h.authorize(authClaims)

	if !authorized {
		log.Printf("[AUTH]   Decision: DENIED")
		h.respondWithError(msg, "authorization denied")
		return
	}

	log.Printf("[AUTH]   Decision: AUTHORIZED as '%s'", userName)
	log.Printf("[AUTH]   Target account: %s", h.targetAccount)
	log.Printf("[AUTH]   Server ID (audience): %s", authClaims.Server.ID)

	// Create a user JWT for the authorized user
	// Use Server.ID as audience for the user JWT
	userJWT, err := h.createUserJWT(userNKey, userName, permissions, authClaims.Server.ID)
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to create user JWT: %v", err)
		h.respondWithError(msg, "internal error creating user JWT")
		return
	}
	log.Printf("[AUTH]   User JWT created")

	// Create the authorization response
	responseJWT, err := h.createAuthResponse(authClaims, userJWT)
	if err != nil {
		log.Printf("[AUTH] ERROR: Failed to create auth response: %v", err)
		h.respondWithError(msg, "internal error creating response")
		return
	}

	// Send response
	if err := msg.Respond([]byte(responseJWT)); err != nil {
		log.Printf("[AUTH] ERROR: Failed to send response: %v", err)
		return
	}

	log.Printf("[AUTH]   Response sent successfully")
}

// authorize makes the authorization decision using the pluggable Authorizer.
func (h *AuthCalloutHandler) authorize(claims *jwt.AuthorizationRequestClaims) (bool, string, jwt.UserPermissionLimits) {
	// Extract the token from connect options
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

	// Convert auth.Permissions to jwt.UserPermissionLimits
	permissions := jwt.UserPermissionLimits{
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

	return true, userName, permissions
}

// initAuthorizer creates the auth backend based on configuration.
func initAuthorizer(ctx context.Context, backend, jwksURL, jwksPath, jwtIssuer, jwtAudience string) auth.Authorizer {
	switch backend {
	case "k8s-oidc":
		log.Println("Initializing K8s OIDC auth backend...")

		// Initialize JWT validator
		var validator *jwtvalidator.Validator
		var err error
		if jwksPath != "" {
			validator, err = jwtvalidator.NewValidatorFromFile(jwksPath, jwtIssuer, jwtAudience)
		} else {
			validator, err = jwtvalidator.NewValidatorFromURL(jwksURL, jwtIssuer, jwtAudience)
		}
		if err != nil {
			log.Fatalf("Failed to initialize JWT validator: %v", err)
		}
		log.Println("  JWT validator initialized")

		// Initialize K8s client + informer cache
		k8sConfig, err := rest.InClusterConfig()
		if err != nil {
			log.Fatalf("Failed to get in-cluster K8s config: %v", err)
		}
		clientset, err := kubernetes.NewForConfig(k8sConfig)
		if err != nil {
			log.Fatalf("Failed to create K8s clientset: %v", err)
		}
		factory := informers.NewSharedInformerFactory(clientset, 0)
		k8sClient := k8s.NewClient(factory)
		k8sClient.Start(ctx)
		log.Println("  K8s ServiceAccount cache initialized")

		return auth.NewK8sOIDCAuthorizer(validator, k8sClient)

	case "allow-all":
		log.Println("Using allow-all auth backend (all connections authorized)")
		return &auth.AllowAllAuthorizer{}

	default:
		log.Fatalf("Unknown auth backend: %s", backend)
		return nil
	}
}

// createUserJWT creates a user JWT for the authorized user
func (h *AuthCalloutHandler) createUserJWT(userNKey, userName string, permissions jwt.UserPermissionLimits, audience string) (string, error) {
	claims := jwt.NewUserClaims(userNKey)
	claims.Name = userName
	claims.IssuedAt = time.Now().Unix()
	claims.IssuerAccount = h.targetAccount

	if audience != "" {
		claims.Audience = audience
	}

	// Copy permissions and limits from the provided UserPermissionLimits
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

// respondWithError sends an error response
func (h *AuthCalloutHandler) respondWithError(msg *nats.Msg, errMsg string) {
	response := jwt.NewAuthorizationResponseClaims("")
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
