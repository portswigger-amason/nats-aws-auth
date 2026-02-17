// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/portswigger/nats-aws-auth/internal/auth"
	jwtvalidator "github.com/portswigger/nats-aws-auth/internal/jwt"
	"github.com/portswigger/nats-aws-auth/internal/k8s"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type natsConnection struct {
	nc              *nats.Conn
	operatorKey     *KMSKey
	sysKey          *KMSKey
	operatorSigner  jwt.SignFn
	operatorKP      *dummyKeyPair
}

type accountConfig struct {
	authClaims *jwt.AccountClaims
	appClaims  *jwt.AccountClaims
	signingKP  nkeys.KeyPair
	authUserKP nkeys.KeyPair
}

func runAuthService(ctx context.Context, authAccountName, appAccountName, region, natsURL string, authorizer auth.Authorizer) {
	log.Println("NATS Client with KMS-signed credentials")
	log.Println()

	client := setupAWSForAuthService(ctx, region)
	conn := setupNATSConnection(ctx, client, natsURL)
	defer conn.nc.Close()

	accounts := fetchAndConfigureAccounts(ctx, client, conn, authAccountName, appAccountName)

	startAuthService(conn.nc, accounts, authAccountName, appAccountName, natsURL, authorizer)
}

func setupAWSForAuthService(ctx context.Context, region string) *kms.Client {
	log.Println("Step 1: Loading AWS configuration...")
	cfg, err := loadAWSConfig(ctx, region)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}
	client := kms.NewFromConfig(cfg)
	log.Println("  AWS config loaded successfully")
	log.Println()
	return client
}

func setupNATSConnection(ctx context.Context, client *kms.Client, natsURL string) *natsConnection {
	operatorKey := lookupOperatorKey(ctx, client)
	sysKey := lookupSysAccountKey(ctx, client)

	userKP := generateUserKeyPair()
	userJWT := createSysUserJWT(ctx, client, userKP, sysKey)

	nc := connectToNATSServer(natsURL, userJWT, userKP)
	testNATSConnection(nc)

	operatorSigner := createKMSSigner(ctx, client, operatorKey.KeyID)
	operatorKP := &dummyKeyPair{pubKey: operatorKey.PublicKey}

	return &natsConnection{
		nc:              nc,
		operatorKey:     operatorKey,
		sysKey:          sysKey,
		operatorSigner:  operatorSigner,
		operatorKP:      operatorKP,
	}
}

func lookupOperatorKey(ctx context.Context, client *kms.Client) *KMSKey {
	log.Println("Step 2: Looking up Operator key from KMS (alias: nats-operator)...")
	operatorKey, err := getExistingKMSKey(ctx, client, "alias/nats-operator", nkeys.PrefixByteOperator)
	if err != nil {
		log.Fatalf("Failed to find Operator key in KMS: %v\n\nPlease run with -generate first to create the KMS keys.", err)
	}
	log.Printf("  Operator Public Key: %s", operatorKey.PublicKey)
	log.Printf("  KMS Key ID: %s", operatorKey.KeyID)
	log.Println()
	return operatorKey
}

func lookupSysAccountKey(ctx context.Context, client *kms.Client) *KMSKey {
	log.Println("Step 3: Looking up SYS Account key from KMS (alias: nats-sys-account)...")
	sysKey, err := getExistingKMSKey(ctx, client, "alias/nats-sys-account", nkeys.PrefixByteAccount)
	if err != nil {
		log.Fatalf("Failed to find SYS Account key in KMS: %v\n\nPlease run with -generate first to create the KMS keys.", err)
	}
	log.Printf("  SYS Account Public Key: %s", sysKey.PublicKey)
	log.Printf("  KMS Key ID: %s", sysKey.KeyID)
	log.Println()
	return sysKey
}

func generateUserKeyPair() nkeys.KeyPair {
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
	return userKP
}

func createSysUserJWT(ctx context.Context, client *kms.Client, userKP nkeys.KeyPair, sysKey *KMSKey) string {
	log.Println("Step 5: Creating user JWT signed by SYS account (via KMS)...")
	signer := createKMSSigner(ctx, client, sysKey.KeyID)

	userPubKey, _ := userKP.PublicKey()
	userJWT, err := createUserJWT(userPubKey, sysKey.PublicKey, signer)
	if err != nil {
		log.Fatalf("Failed to create user JWT: %v", err)
	}
	log.Println("  User JWT created successfully")
	log.Println()
	return userJWT
}

func connectToNATSServer(natsURL, userJWT string, userKP nkeys.KeyPair) *nats.Conn {
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
	log.Println("  Successfully connected to NATS!")
	log.Println()
	return nc
}

func testNATSConnection(nc *nats.Conn) {
	log.Println("Step 7: Testing connection...")

	sub, err := nc.SubscribeSync("test.subject")
	if err != nil {
		log.Fatalf("Failed to subscribe: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	testMsg := []byte("Hello from KMS-signed NATS client!")
	if err := nc.Publish("test.subject", testMsg); err != nil {
		log.Fatalf("Failed to publish: %v", err)
	}
	log.Println("  Published test message")

	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		log.Fatalf("Failed to receive message: %v", err)
	}
	log.Printf("  Received message: %s", string(msg.Data))
	log.Println()

	log.Println("Success! Connection and messaging work correctly.")
	log.Println()
}

func fetchAndConfigureAccounts(ctx context.Context, client *kms.Client, conn *natsConnection, authAccountName, appAccountName string) *accountConfig {
	signingKP := generateSigningKeyPair()
	authJWT, appJWT := fetchAccountsFromNATS(conn.nc, authAccountName, appAccountName)

	appClaims := ensureAppAccountExists(conn, appJWT, appAccountName)
	authClaims := decodeAuthAccount(authJWT, authAccountName)

	authUserKP := createAuthUserKeyPair()

	updateAuthAccount(conn, authClaims, signingKP, authUserKP)
	updateAppAccount(conn, appClaims, signingKP)

	createSentinelCredentials(authClaims, signingKP)

	return &accountConfig{
		authClaims: authClaims,
		appClaims:  appClaims,
		signingKP:  signingKP,
		authUserKP: authUserKP,
	}
}

func generateSigningKeyPair() nkeys.KeyPair {
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
	return signingKP
}

func fetchAccountsFromNATS(nc *nats.Conn, authAccountName, appAccountName string) (string, string) {
	log.Println("Step 8: Fetching all account JWTs from NATS server...")
	log.Println("  Using $SYS.REQ.CLAIMS.PACK to pull all accounts")

	inbox := nats.NewInbox()
	log.Printf("  Response inbox: %s", inbox)

	claimsSub, err := nc.SubscribeSync(inbox)
	if err != nil {
		log.Fatalf("Failed to subscribe to inbox: %v", err)
	}
	defer func() { _ = claimsSub.Unsubscribe() }()

	if err := nc.PublishRequest("$SYS.REQ.CLAIMS.PACK", inbox, nil); err != nil {
		log.Fatalf("Failed to request claims pack: %v", err)
	}
	log.Println("  Request sent, waiting for responses...")
	log.Println()

	return collectAccountJWTs(claimsSub, authAccountName, appAccountName)
}

func collectAccountJWTs(sub *nats.Subscription, authAccountName, appAccountName string) (string, string) {
	var authJWT, appJWT string
	accountCount := 0

	for {
		resp, err := sub.NextMsg(2 * time.Second)
		if err != nil {
			log.Printf("  Timeout or error waiting for response: %v", err)
			break
		}

		msg := string(resp.Data)
		if msg == "" {
			log.Println("  Received empty response (end of stream)")
			break
		}

		parts := strings.Split(msg, "|")
		if len(parts) != 2 {
			log.Printf("  WARNING: Unexpected response format: %s", msg)
			continue
		}

		pubkey := parts[0]
		jwtToken := parts[1]
		accountCount++

		log.Printf("  Account %d: %s", accountCount, pubkey)

		if claims, err := jwt.DecodeAccountClaims(jwtToken); err == nil {
			logAccountInfo(claims)

			if claims.Name == authAccountName {
				log.Println("    ** This is the AUTH account **")
				authJWT = jwtToken
			}

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

	return authJWT, appJWT
}

func logAccountInfo(claims *jwt.AccountClaims) {
	log.Printf("    Name: %s", claims.Name)
	log.Printf("    Subject: %s", claims.Subject)
	log.Printf("    Issued At: %s", time.Unix(claims.IssuedAt, 0).Format(time.RFC3339))
	if len(claims.SigningKeys) > 0 {
		log.Printf("    Signing Keys: %v", claims.SigningKeys.Keys())
	}
}

func ensureAppAccountExists(conn *natsConnection, appJWT, appAccountName string) *jwt.AccountClaims {
	if appJWT != "" {
		appClaims, err := jwt.DecodeAccountClaims(appJWT)
		if err != nil {
			log.Fatalf("Failed to decode APP account JWT: %v", err)
		}
		return appClaims
	}

	log.Println("APP account not found, creating new APP account...")

	appKP, err := nkeys.CreateAccount()
	if err != nil {
		log.Fatalf("Failed to create APP account keypair: %v", err)
	}
	appPubKey, err := appKP.PublicKey()
	if err != nil {
		log.Fatalf("Failed to get APP account public key: %v", err)
	}
	log.Printf("  APP account public key: %s", appPubKey)

	appClaims := jwt.NewAccountClaims(appPubKey)
	appClaims.Name = appAccountName
	appClaims.IssuedAt = time.Now().Unix()

	appJWT, err = appClaims.EncodeWithSigner(conn.operatorKP, conn.operatorSigner)
	if err != nil {
		log.Fatalf("Failed to encode APP account JWT: %v", err)
	}
	log.Println("  APP account JWT created")

	updateSubject := "$SYS.REQ.CLAIMS.UPDATE"
	updateResp, err := conn.nc.Request(updateSubject, []byte(appJWT), 5*time.Second)
	if err != nil {
		log.Fatalf("Failed to publish APP account JWT: %v", err)
	}
	log.Printf("  Response from server: %s", string(updateResp.Data))
	log.Println()

	return appClaims
}

func decodeAuthAccount(authJWT, authAccountName string) *jwt.AccountClaims {
	authClaims, err := jwt.DecodeAccountClaims(authJWT)
	if err != nil {
		log.Fatalf("Failed to decode AUTH account JWT: %v", err)
	}
	log.Printf("Found AUTH account: %s (public key: %s)", authClaims.Name, authClaims.Subject)
	log.Println()
	return authClaims
}

func createAuthUserKeyPair() nkeys.KeyPair {
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
	return authUserKP
}

func updateAuthAccount(conn *natsConnection, authClaims *jwt.AccountClaims, signingKP, authUserKP nkeys.KeyPair) {
	log.Println("Step 10: Configuring AUTH account...")

	signingPubKey, _ := signingKP.PublicKey()
	authUserPubKey, _ := authUserKP.PublicKey()

	if authClaims.SigningKeys == nil {
		authClaims.SigningKeys = make(jwt.SigningKeys)
	}
	authClaims.SigningKeys.Add(signingPubKey)
	log.Printf("  Added signing key: %s", signingPubKey)

	authClaims.Authorization = jwt.ExternalAuthorization{
		AuthUsers:       []string{authUserPubKey},
		AllowedAccounts: []string{"*"},
	}
	log.Printf("  Enabled external authorization")
	log.Printf("  Auth user (bypasses callout): %s", authUserPubKey)

	authClaims.IssuedAt = time.Now().Unix()
	log.Println()

	publishUpdatedAuthAccount(conn, authClaims)
}

func publishUpdatedAuthAccount(conn *natsConnection, authClaims *jwt.AccountClaims) {
	log.Println("Step 11: Re-signing AUTH account JWT with Operator (via KMS)...")

	updatedAuthJWT, err := authClaims.EncodeWithSigner(conn.operatorKP, conn.operatorSigner)
	if err != nil {
		log.Fatalf("Failed to encode updated AUTH account JWT: %v", err)
	}
	log.Println("  AUTH account JWT re-signed successfully")
	log.Println()

	log.Println("Step 12: Publishing updated AUTH account JWT to NATS...")

	updateSubject := "$SYS.REQ.CLAIMS.UPDATE"
	updateResp, err := conn.nc.Request(updateSubject, []byte(updatedAuthJWT), 5*time.Second)
	if err != nil {
		log.Fatalf("Failed to publish updated JWT: %v", err)
	}
	log.Printf("  Response from server: %s", string(updateResp.Data))
	log.Println()

	log.Println("Success! AUTH account configured with:")
	log.Println("  - Signing key for issuing user JWTs")
	log.Println("  - External authorization (auth callout) enabled")
	log.Println()
}

func updateAppAccount(conn *natsConnection, appClaims *jwt.AccountClaims, signingKP nkeys.KeyPair) {
	log.Println("Step 13: Configuring APP account (signing key + JetStream)...")

	signingPubKey, _ := signingKP.PublicKey()

	if appClaims.SigningKeys == nil {
		appClaims.SigningKeys = make(jwt.SigningKeys)
	}
	appClaims.SigningKeys.Add(signingPubKey)
	log.Printf("  Added signing key: %s", signingPubKey)

	appClaims.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage:        -1,
		DiskStorage:          -1,
		Streams:              -1,
		Consumer:             -1,
		MaxAckPending:        -1,
		MemoryMaxStreamBytes: -1,
		DiskMaxStreamBytes:   -1,
		MaxBytesRequired:     false,
	}
	log.Println("  Enabled JetStream with unlimited limits")

	appClaims.IssuedAt = time.Now().Unix()

	updatedAppJWT, err := appClaims.EncodeWithSigner(conn.operatorKP, conn.operatorSigner)
	if err != nil {
		log.Fatalf("Failed to encode updated APP account JWT: %v", err)
	}
	log.Println("  APP account JWT re-signed successfully")

	updateSubject := "$SYS.REQ.CLAIMS.UPDATE"
	appUpdateResp, err := conn.nc.Request(updateSubject, []byte(updatedAppJWT), 5*time.Second)
	if err != nil {
		log.Fatalf("Failed to publish updated APP account JWT: %v", err)
	}
	log.Printf("  Response from server: %s", string(appUpdateResp.Data))
	log.Println()
}

func createSentinelCredentials(authClaims *jwt.AccountClaims, signingKP nkeys.KeyPair) {
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

	if err := os.WriteFile("sentinel.creds", []byte(sentinelCreds), 0600); err != nil {
		log.Printf("  Skipping sentinel.creds file write (read-only filesystem): %v", err)
	} else {
		log.Println("  Sentinel credentials written to: sentinel.creds")
	}
	log.Println()
}

func startAuthService(nc *nats.Conn, accounts *accountConfig, authAccountName, appAccountName, natsURL string, authorizer auth.Authorizer) {
	authUserJWT := createAuthUserJWTForService(accounts)

	authNC := connectAsAuthUser(natsURL, authUserJWT, accounts.authUserKP)
	defer authNC.Close()

	testAuthUserMessaging(authNC)
	startAuthCalloutHandler(authNC, accounts, appAccountName, authorizer)
}

func createAuthUserJWTForService(accounts *accountConfig) string {
	log.Println("Step 14: Creating auth user JWT signed by signing key...")
	authUserPubKey, _ := accounts.authUserKP.PublicKey()
	signingPubKey, _ := accounts.signingKP.PublicKey()

	log.Printf("  Issuer Account (AUTH): %s", accounts.authClaims.Subject)
	log.Printf("  Signing Key (Issuer): %s", signingPubKey)

	authUserJWT, err := createUserJWTWithKey(authUserPubKey, "auth", accounts.authClaims.Subject, accounts.signingKP)
	if err != nil {
		log.Fatalf("Failed to create auth user JWT: %v", err)
	}
	log.Println("  User JWT created successfully")
	log.Println()

	return authUserJWT
}

func connectAsAuthUser(natsURL, authUserJWT string, authUserKP nkeys.KeyPair) *nats.Conn {
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
	log.Println("  Successfully connected as auth user!")
	log.Println()
	return authNC
}

func testAuthUserMessaging(authNC *nats.Conn) {
	log.Println("Step 17: Testing messaging as auth user...")
	testSubject := "auth.test.message"

	authSub, err := authNC.SubscribeSync(testSubject)
	if err != nil {
		log.Fatalf("Failed to subscribe as auth user: %v", err)
	}
	defer func() { _ = authSub.Unsubscribe() }()
	log.Printf("  Subscribed to: %s", testSubject)

	testMessage := []byte("Hello from auth user in AUTH account!")
	if err := authNC.Publish(testSubject, testMessage); err != nil {
		log.Fatalf("Failed to publish as auth user: %v", err)
	}
	log.Println("  Published test message")

	authMsg, err := authSub.NextMsg(2 * time.Second)
	if err != nil {
		log.Fatalf("Failed to receive message as auth user: %v", err)
	}
	log.Printf("  Received message: %s", string(authMsg.Data))
	log.Println()

	logSuccessfulSetup()
}

func logSuccessfulSetup() {
	log.Println("SUCCESS! Setup completed:")
	log.Println("  ✓ Connected to NATS as SYS user with KMS-signed credentials")
	log.Println("  ✓ Fetched all account JWTs from NATS server")
	log.Println("  ✓ Generated signing key for AUTH and APP accounts")
	log.Println("  ✓ Configured external authorization (auth callout) on AUTH account")
	log.Println("  ✓ Created APP account for authorized users")
	log.Println("  ✓ Created 'auth' user in AUTH account (bypasses callout)")
	log.Println("  ✓ Connected as 'auth' user and verified messaging")
	log.Println()
}

func startAuthCalloutHandler(authNC *nats.Conn, accounts *accountConfig, appAccountName string, authorizer auth.Authorizer) {
	log.Println("Step 18: Starting auth callout handler...")
	authCalloutSubject := "$SYS.REQ.USER.AUTH"

	handler := &AuthCalloutHandler{
		signingKP:      accounts.signingKP,
		authAccountPub: accounts.authClaims.Subject,
		targetAccount:  accounts.appClaims.Subject,
		authorizer:     authorizer,
	}
	log.Printf("  Auth callout will issue users for APP account: %s", accounts.appClaims.Subject)

	authCalloutSub, err := authNC.Subscribe(authCalloutSubject, handler.HandleAuthRequest)
	if err != nil {
		log.Fatalf("Failed to subscribe to auth callout: %v", err)
	}
	defer func() { _ = authCalloutSub.Unsubscribe() }()

	log.Printf("  Subscribed to: %s", authCalloutSubject)
	log.Println()

	log.Println("===========================================")
	log.Println("Auth callout service is now running!")
	log.Println("===========================================")
	log.Println()
	log.Println("The service will authorize incoming connections.")
	log.Println()

	go startHealthServer(authNC)

	select {}
}

// initAuthorizer creates the auth backend based on configuration
func initAuthorizer(ctx context.Context, backend, jwksURL, jwksPath, jwtIssuer, jwtAudience string) auth.Authorizer {
	switch backend {
	case "k8s-oidc":
		return initK8sOIDCAuthorizer(ctx, jwksURL, jwksPath, jwtIssuer, jwtAudience)
	case "allow-all":
		log.Println("Using allow-all auth backend (all connections authorized)")
		return &auth.AllowAllAuthorizer{}
	default:
		log.Fatalf("Unknown auth backend: %s", backend)
		return nil
	}
}

func initK8sOIDCAuthorizer(ctx context.Context, jwksURL, jwksPath, jwtIssuer, jwtAudience string) auth.Authorizer {
	log.Println("Initializing K8s OIDC auth backend...")

	validator := initJWTValidator(jwksPath, jwksURL, jwtIssuer, jwtAudience)
	k8sClient := initK8sClient(ctx)

	return auth.NewK8sOIDCAuthorizer(validator, k8sClient)
}

func initJWTValidator(jwksPath, jwksURL, jwtIssuer, jwtAudience string) *jwtvalidator.Validator {
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
	return validator
}

func initK8sClient(ctx context.Context) *k8s.Client {
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
	return k8sClient
}

func createUserJWT(userPubKey, issuerPubKey string, signer jwt.SignFn) (string, error) {
	claims := jwt.NewUserClaims(userPubKey)
	claims.Name = "sys"
	claims.IssuedAt = time.Now().Unix()

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
	claims.IssuerAccount = accountPubKey

	token, err := claims.Encode(signingKeyPair)
	if err != nil {
		return "", fmt.Errorf("failed to encode user JWT: %w", err)
	}

	return token, nil
}

func createSentinelUserJWTForAuthService(userPubKey, accountPubKey string, signingKeyPair nkeys.KeyPair) (string, error) {
	claims := jwt.NewUserClaims(userPubKey)
	claims.Name = "sentinel"
	claims.IssuedAt = time.Now().Unix()
	claims.IssuerAccount = accountPubKey

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

func startHealthServer(nc *nats.Conn) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if !nc.IsConnected() {
			http.Error(w, "NATS disconnected", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "ok")
	})

	log.Println("Health server listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("Health server failed: %v", err)
	}
}
