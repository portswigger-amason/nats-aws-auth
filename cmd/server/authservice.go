// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"context"
	"fmt"
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
	"go.uber.org/zap"
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
}

func runAuthService(ctx context.Context, authAccountName, appAccountName, region, natsURL string, authorizer auth.Authorizer, logger *zap.Logger) {
	logger.Info("NATS Client with KMS-signed credentials")

	client := setupAWSForAuthService(ctx, region, logger)
	conn := setupNATSConnection(ctx, client, natsURL, logger)
	defer conn.nc.Close()

	accounts := fetchAndConfigureAccounts(ctx, client, conn, authAccountName, appAccountName, logger)

	startAuthService(conn.nc, accounts, authAccountName, appAccountName, natsURL, authorizer, logger)
}

func setupAWSForAuthService(ctx context.Context, region string, logger *zap.Logger) *kms.Client {
	logger.Info("Loading AWS configuration...")
	cfg, err := loadAWSConfig(ctx, region)
	if err != nil {
		logger.Fatal("Failed to load AWS config", zap.Error(err))
	}
	client := kms.NewFromConfig(cfg)
	logger.Debug("AWS config loaded successfully")
	return client
}

func setupNATSConnection(ctx context.Context, client *kms.Client, natsURL string, logger *zap.Logger) *natsConnection {
	operatorKey := lookupOperatorKey(ctx, client, logger)
	sysKey := lookupSysAccountKey(ctx, client, logger)

	userKP := generateUserKeyPair(logger)
	userJWT := createSysUserJWT(ctx, client, userKP, sysKey, logger)

	nc := connectToNATSServer(natsURL, userJWT, userKP, logger)
	testNATSConnection(nc, logger)

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

func lookupOperatorKey(ctx context.Context, client *kms.Client, logger *zap.Logger) *KMSKey {
	logger.Info("Looking up Operator key from KMS (alias: nats-operator)...")
	operatorKey, err := getExistingKMSKey(ctx, client, "alias/nats-operator", nkeys.PrefixByteOperator)
	if err != nil {
		logger.Fatal("Failed to find Operator key in KMS\n\nPlease run with -generate first to create the KMS keys.", zap.Error(err))
	}
	logger.Debug("Operator Public Key", zap.String("publicKey", operatorKey.PublicKey))
	logger.Debug("KMS Key ID", zap.String("keyID", operatorKey.KeyID))
	return operatorKey
}

func lookupSysAccountKey(ctx context.Context, client *kms.Client, logger *zap.Logger) *KMSKey {
	logger.Info("Looking up SYS Account key from KMS (alias: nats-sys-account)...")
	sysKey, err := getExistingKMSKey(ctx, client, "alias/nats-sys-account", nkeys.PrefixByteAccount)
	if err != nil {
		logger.Fatal("Failed to find SYS Account key in KMS\n\nPlease run with -generate first to create the KMS keys.", zap.Error(err))
	}
	logger.Debug("SYS Account Public Key", zap.String("publicKey", sysKey.PublicKey))
	logger.Debug("KMS Key ID", zap.String("keyID", sysKey.KeyID))
	return sysKey
}

func generateUserKeyPair(logger *zap.Logger) nkeys.KeyPair {
	logger.Info("Generating in-memory user keypair...")
	userKP, err := nkeys.CreateUser()
	if err != nil {
		logger.Fatal("Failed to create user keypair", zap.Error(err))
	}
	userPubKey, err := userKP.PublicKey()
	if err != nil {
		logger.Fatal("Failed to get user public key", zap.Error(err))
	}
	logger.Debug("User public key", zap.String("publicKey", userPubKey))
	return userKP
}

func createSysUserJWT(ctx context.Context, client *kms.Client, userKP nkeys.KeyPair, sysKey *KMSKey, logger *zap.Logger) string {
	logger.Info("Creating user JWT signed by SYS account (via KMS)...")
	signer := createKMSSigner(ctx, client, sysKey.KeyID)

	userPubKey, _ := userKP.PublicKey()
	userJWT, err := createUserJWT(userPubKey, sysKey.PublicKey, signer)
	if err != nil {
		logger.Fatal("Failed to create user JWT", zap.Error(err))
	}
	logger.Debug("User JWT created successfully")
	return userJWT
}

func connectToNATSServer(natsURL, userJWT string, userKP nkeys.KeyPair, logger *zap.Logger) *nats.Conn {
	logger.Info("Connecting to NATS...", zap.String("url", natsURL))
	nc, err := nats.Connect(natsURL, nats.UserJWT(
		func() (string, error) {
			return userJWT, nil
		},
		func(nonce []byte) ([]byte, error) {
			return userKP.Sign(nonce)
		},
	))
	if err != nil {
		logger.Fatal("Failed to connect to NATS", zap.Error(err))
	}
	logger.Debug("Successfully connected to NATS!")
	return nc
}

func testNATSConnection(nc *nats.Conn, logger *zap.Logger) {
	logger.Info("Testing connection...")

	sub, err := nc.SubscribeSync("test.subject")
	if err != nil {
		logger.Fatal("Failed to subscribe", zap.Error(err))
	}
	defer func() { _ = sub.Unsubscribe() }()

	testMsg := []byte("Hello from KMS-signed NATS client!")
	if err := nc.Publish("test.subject", testMsg); err != nil {
		logger.Fatal("Failed to publish", zap.Error(err))
	}
	logger.Debug("Published test message")

	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		logger.Fatal("Failed to receive message", zap.Error(err))
	}
	logger.Debug("Received message", zap.String("data", string(msg.Data)))

	logger.Info("Success! Connection and messaging work correctly.")
}

func fetchAndConfigureAccounts(ctx context.Context, client *kms.Client, conn *natsConnection, authAccountName, appAccountName string, logger *zap.Logger) *accountConfig {
	signingKP := generateSigningKeyPair(logger)
	authJWT, appJWT := fetchAccountsFromNATS(conn.nc, authAccountName, appAccountName, logger)

	appClaims := ensureAppAccountExists(conn, appJWT, appAccountName, logger)
	authClaims := decodeAuthAccount(authJWT, authAccountName, logger)

	authUserKP := createAuthUserKeyPair(logger)

	updateAuthAccount(conn, authClaims, signingKP, authUserKP, logger)
	updateAppAccount(conn, appClaims, signingKP, logger)

	createSentinelCredentials(authClaims, signingKP, logger)

	return &accountConfig{
		authClaims: authClaims,
		appClaims:  appClaims,
		signingKP:  signingKP,
	}
}

func generateSigningKeyPair(logger *zap.Logger) nkeys.KeyPair {
	logger.Info("Generating in-memory signing keypair for AUTH account...")
	signingKP, err := nkeys.CreateAccount()
	if err != nil {
		logger.Fatal("Failed to create signing keypair", zap.Error(err))
	}
	signingPubKey, err := signingKP.PublicKey()
	if err != nil {
		logger.Fatal("Failed to get signing public key", zap.Error(err))
	}
	logger.Debug("Signing key public key", zap.String("publicKey", signingPubKey))
	return signingKP
}

func fetchAccountsFromNATS(nc *nats.Conn, authAccountName, appAccountName string, logger *zap.Logger) (string, string) {
	logger.Info("Fetching all account JWTs from NATS server...")
	logger.Debug("Using $SYS.REQ.CLAIMS.PACK to pull all accounts")

	inbox := nats.NewInbox()
	logger.Debug("Response inbox", zap.String("inbox", inbox))

	claimsSub, err := nc.SubscribeSync(inbox)
	if err != nil {
		logger.Fatal("Failed to subscribe to inbox", zap.Error(err))
	}
	defer func() { _ = claimsSub.Unsubscribe() }()

	if err := nc.PublishRequest("$SYS.REQ.CLAIMS.PACK", inbox, nil); err != nil {
		logger.Fatal("Failed to request claims pack", zap.Error(err))
	}
	logger.Debug("Request sent, waiting for responses...")

	return collectAccountJWTs(claimsSub, authAccountName, appAccountName, logger)
}

func collectAccountJWTs(sub *nats.Subscription, authAccountName, appAccountName string, logger *zap.Logger) (string, string) {
	var authJWT, appJWT string
	accountCount := 0

	for {
		resp, err := sub.NextMsg(2 * time.Second)
		if err != nil {
			logger.Debug("Timeout or error waiting for response", zap.Error(err))
			break
		}

		msg := string(resp.Data)
		if msg == "" {
			logger.Debug("Received empty response (end of stream)")
			break
		}

		parts := strings.Split(msg, "|")
		if len(parts) != 2 {
			logger.Debug("WARNING: Unexpected response format", zap.String("msg", msg))
			continue
		}

		pubkey := parts[0]
		jwtToken := parts[1]
		accountCount++

		logger.Debug("Account received", zap.Int("account", accountCount), zap.String("pubkey", pubkey))

		if claims, err := jwt.DecodeAccountClaims(jwtToken); err == nil {
			logAccountInfo(claims, logger)

			if claims.Name == authAccountName {
				logger.Debug("** This is the AUTH account **")
				authJWT = jwtToken
			}

			if claims.Name == appAccountName {
				logger.Debug("** This is the APP account **")
				appJWT = jwtToken
			}
		} else {
			logger.Debug("Failed to decode", zap.Error(err))
		}
	}

	logger.Debug("Total accounts received", zap.Int("count", accountCount))

	if authJWT == "" {
		logger.Fatal("AUTH account JWT not found in response")
	}

	return authJWT, appJWT
}

func logAccountInfo(claims *jwt.AccountClaims, logger *zap.Logger) {
	logger.Debug("Name", zap.String("name", claims.Name))
	logger.Debug("Subject", zap.String("subject", claims.Subject))
	logger.Debug("Issued At", zap.String("issuedAt", time.Unix(claims.IssuedAt, 0).Format(time.RFC3339)))
	if len(claims.SigningKeys) > 0 {
		logger.Debug("Signing Keys", zap.Strings("keys", claims.SigningKeys.Keys()))
	}
}

func ensureAppAccountExists(conn *natsConnection, appJWT, appAccountName string, logger *zap.Logger) *jwt.AccountClaims {
	if appJWT != "" {
		appClaims, err := jwt.DecodeAccountClaims(appJWT)
		if err != nil {
			logger.Fatal("Failed to decode APP account JWT", zap.Error(err))
		}
		return appClaims
	}

	logger.Info("APP account not found, creating new APP account...")

	appKP, err := nkeys.CreateAccount()
	if err != nil {
		logger.Fatal("Failed to create APP account keypair", zap.Error(err))
	}
	appPubKey, err := appKP.PublicKey()
	if err != nil {
		logger.Fatal("Failed to get APP account public key", zap.Error(err))
	}
	logger.Debug("APP account public key", zap.String("publicKey", appPubKey))

	appClaims := jwt.NewAccountClaims(appPubKey)
	appClaims.Name = appAccountName
	appClaims.IssuedAt = time.Now().Unix()

	appJWT, err = appClaims.EncodeWithSigner(conn.operatorKP, conn.operatorSigner)
	if err != nil {
		logger.Fatal("Failed to encode APP account JWT", zap.Error(err))
	}
	logger.Debug("APP account JWT created")

	updateSubject := "$SYS.REQ.CLAIMS.UPDATE"
	updateResp, err := conn.nc.Request(updateSubject, []byte(appJWT), 5*time.Second)
	if err != nil {
		logger.Fatal("Failed to publish APP account JWT", zap.Error(err))
	}
	logger.Debug("Response from server", zap.String("response", string(updateResp.Data)))

	return appClaims
}

func decodeAuthAccount(authJWT, authAccountName string, logger *zap.Logger) *jwt.AccountClaims {
	authClaims, err := jwt.DecodeAccountClaims(authJWT)
	if err != nil {
		logger.Fatal("Failed to decode AUTH account JWT", zap.Error(err))
	}
	logger.Debug("Found AUTH account", zap.String("name", authClaims.Name), zap.String("publicKey", authClaims.Subject))
	return authClaims
}

func createAuthUserKeyPair(logger *zap.Logger) nkeys.KeyPair {
	logger.Info("Creating auth user keypair...")
	authUserKP, err := nkeys.CreateUser()
	if err != nil {
		logger.Fatal("Failed to create auth user keypair", zap.Error(err))
	}
	authUserPubKey, err := authUserKP.PublicKey()
	if err != nil {
		logger.Fatal("Failed to get auth user public key", zap.Error(err))
	}
	logger.Debug("Auth user public key", zap.String("publicKey", authUserPubKey))
	return authUserKP
}

func updateAuthAccount(conn *natsConnection, authClaims *jwt.AccountClaims, signingKP, authUserKP nkeys.KeyPair, logger *zap.Logger) {
	logger.Info("Configuring AUTH account...")

	signingPubKey, _ := signingKP.PublicKey()
	authUserPubKey, _ := authUserKP.PublicKey()

	if authClaims.SigningKeys == nil {
		authClaims.SigningKeys = make(jwt.SigningKeys)
	}
	authClaims.SigningKeys.Add(signingPubKey)
	logger.Debug("Added signing key", zap.String("signingKey", signingPubKey))

	authClaims.Authorization = jwt.ExternalAuthorization{
		AuthUsers:       []string{authUserPubKey},
		AllowedAccounts: []string{"*"},
	}
	logger.Debug("Enabled external authorization")
	logger.Debug("Auth user (bypasses callout)", zap.String("authUser", authUserPubKey))

	authClaims.IssuedAt = time.Now().Unix()

	publishUpdatedAuthAccount(conn, authClaims, logger)
}

func publishUpdatedAuthAccount(conn *natsConnection, authClaims *jwt.AccountClaims, logger *zap.Logger) {
	logger.Info("Re-signing AUTH account JWT with Operator (via KMS)...")

	updatedAuthJWT, err := authClaims.EncodeWithSigner(conn.operatorKP, conn.operatorSigner)
	if err != nil {
		logger.Fatal("Failed to encode updated AUTH account JWT", zap.Error(err))
	}
	logger.Debug("AUTH account JWT re-signed successfully")

	logger.Info("Publishing updated AUTH account JWT to NATS...")

	updateSubject := "$SYS.REQ.CLAIMS.UPDATE"
	updateResp, err := conn.nc.Request(updateSubject, []byte(updatedAuthJWT), 5*time.Second)
	if err != nil {
		logger.Fatal("Failed to publish updated JWT", zap.Error(err))
	}
	logger.Debug("Response from server", zap.String("response", string(updateResp.Data)))

	logger.Info("Success! AUTH account configured with:")
	logger.Debug("- Signing key for issuing user JWTs")
	logger.Debug("- External authorization (auth callout) enabled")
}

func updateAppAccount(conn *natsConnection, appClaims *jwt.AccountClaims, signingKP nkeys.KeyPair, logger *zap.Logger) {
	logger.Info("Configuring APP account (signing key + JetStream)...")

	signingPubKey, _ := signingKP.PublicKey()

	if appClaims.SigningKeys == nil {
		appClaims.SigningKeys = make(jwt.SigningKeys)
	}
	appClaims.SigningKeys.Add(signingPubKey)
	logger.Debug("Added signing key", zap.String("signingKey", signingPubKey))

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
	logger.Debug("Enabled JetStream with unlimited limits")

	appClaims.IssuedAt = time.Now().Unix()

	updatedAppJWT, err := appClaims.EncodeWithSigner(conn.operatorKP, conn.operatorSigner)
	if err != nil {
		logger.Fatal("Failed to encode updated APP account JWT", zap.Error(err))
	}
	logger.Debug("APP account JWT re-signed successfully")

	updateSubject := "$SYS.REQ.CLAIMS.UPDATE"
	appUpdateResp, err := conn.nc.Request(updateSubject, []byte(updatedAppJWT), 5*time.Second)
	if err != nil {
		logger.Fatal("Failed to publish updated APP account JWT", zap.Error(err))
	}
	logger.Debug("Response from server", zap.String("response", string(appUpdateResp.Data)))
}

func createSentinelCredentials(authClaims *jwt.AccountClaims, signingKP nkeys.KeyPair, logger *zap.Logger) {
	logger.Info("Creating sentinel user for auth callout testing...")

	sentinelKP, err := nkeys.CreateUser()
	if err != nil {
		logger.Fatal("Failed to create sentinel keypair", zap.Error(err))
	}
	sentinelPubKey, err := sentinelKP.PublicKey()
	if err != nil {
		logger.Fatal("Failed to get sentinel public key", zap.Error(err))
	}
	sentinelSeed, err := sentinelKP.Seed()
	if err != nil {
		logger.Fatal("Failed to get sentinel seed", zap.Error(err))
	}
	logger.Debug("Sentinel public key", zap.String("publicKey", sentinelPubKey))

	sentinelJWT, err := createSentinelUserJWTForAuthService(sentinelPubKey, authClaims.Subject, signingKP)
	if err != nil {
		logger.Fatal("Failed to create sentinel JWT", zap.Error(err))
	}

	sentinelCreds := fmt.Sprintf(`-----BEGIN NATS USER JWT-----
%s
------END NATS USER JWT------

-----BEGIN USER NKEY SEED-----
%s
------END USER NKEY SEED------
`, sentinelJWT, string(sentinelSeed))

	if err := os.WriteFile("sentinel.creds", []byte(sentinelCreds), 0600); err != nil {
		logger.Fatal("Failed to write sentinel credentials", zap.Error(err))
	}
	logger.Debug("Sentinel credentials written to: sentinel.creds")
}

func startAuthService(nc *nats.Conn, accounts *accountConfig, authAccountName, appAccountName, natsURL string, authorizer auth.Authorizer, logger *zap.Logger) {
	authUserKP := createAuthUserKeyPairForService(logger)
	authUserJWT := createAuthUserJWTForService(accounts, authUserKP, logger)

	authNC := connectAsAuthUser(natsURL, authUserJWT, authUserKP, logger)
	defer authNC.Close()

	testAuthUserMessaging(authNC, logger)
	startAuthCalloutHandler(authNC, accounts, appAccountName, authorizer, logger)
}

func createAuthUserKeyPairForService(logger *zap.Logger) nkeys.KeyPair {
	logger.Info("Creating auth user JWT signed by signing key...")
	authUserKP, err := nkeys.CreateUser()
	if err != nil {
		logger.Fatal("Failed to create auth user keypair", zap.Error(err))
	}
	return authUserKP
}

func createAuthUserJWTForService(accounts *accountConfig, authUserKP nkeys.KeyPair, logger *zap.Logger) string {
	authUserPubKey, _ := authUserKP.PublicKey()
	signingPubKey, _ := accounts.signingKP.PublicKey()

	logger.Debug("Issuer Account (AUTH)", zap.String("issuer", accounts.authClaims.Subject))
	logger.Debug("Signing Key (Issuer)", zap.String("signingKey", signingPubKey))

	authUserJWT, err := createUserJWTWithKey(authUserPubKey, "auth", accounts.authClaims.Subject, accounts.signingKP)
	if err != nil {
		logger.Fatal("Failed to create auth user JWT", zap.Error(err))
	}
	logger.Debug("User JWT created successfully")

	return authUserJWT
}

func connectAsAuthUser(natsURL, authUserJWT string, authUserKP nkeys.KeyPair, logger *zap.Logger) *nats.Conn {
	logger.Info("Connecting to NATS as 'auth' user in AUTH account...")
	authNC, err := nats.Connect(natsURL, nats.UserJWT(
		func() (string, error) {
			return authUserJWT, nil
		},
		func(nonce []byte) ([]byte, error) {
			return authUserKP.Sign(nonce)
		},
	))
	if err != nil {
		logger.Fatal("Failed to connect as auth user", zap.Error(err))
	}
	logger.Debug("Successfully connected as auth user!")
	return authNC
}

func testAuthUserMessaging(authNC *nats.Conn, logger *zap.Logger) {
	logger.Info("Testing messaging as auth user...")
	testSubject := "auth.test.message"

	authSub, err := authNC.SubscribeSync(testSubject)
	if err != nil {
		logger.Fatal("Failed to subscribe as auth user", zap.Error(err))
	}
	defer func() { _ = authSub.Unsubscribe() }()
	logger.Debug("Subscribed to", zap.String("subject", testSubject))

	testMessage := []byte("Hello from auth user in AUTH account!")
	if err := authNC.Publish(testSubject, testMessage); err != nil {
		logger.Fatal("Failed to publish as auth user", zap.Error(err))
	}
	logger.Debug("Published test message")

	authMsg, err := authSub.NextMsg(2 * time.Second)
	if err != nil {
		logger.Fatal("Failed to receive message as auth user", zap.Error(err))
	}
	logger.Debug("Received message", zap.String("data", string(authMsg.Data)))

	logSuccessfulSetup(logger)
}

func logSuccessfulSetup(logger *zap.Logger) {
	logger.Info("SUCCESS! Setup completed:")
	logger.Debug("✓ Connected to NATS as SYS user with KMS-signed credentials")
	logger.Debug("✓ Fetched all account JWTs from NATS server")
	logger.Debug("✓ Generated signing key for AUTH and APP accounts")
	logger.Debug("✓ Configured external authorization (auth callout) on AUTH account")
	logger.Debug("✓ Created APP account for authorized users")
	logger.Debug("✓ Created 'auth' user in AUTH account (bypasses callout)")
	logger.Debug("✓ Connected as 'auth' user and verified messaging")
}

func startAuthCalloutHandler(authNC *nats.Conn, accounts *accountConfig, appAccountName string, authorizer auth.Authorizer, logger *zap.Logger) {
	logger.Info("Starting auth callout handler...")
	authCalloutSubject := "$SYS.REQ.USER.AUTH"

	handler := &AuthCalloutHandler{
		signingKP:      accounts.signingKP,
		authAccountPub: accounts.authClaims.Subject,
		targetAccount:  accounts.appClaims.Subject,
		authorizer:     authorizer,
	}
	logger.Debug("Auth callout will issue users for APP account", zap.String("appAccount", accounts.appClaims.Subject))

	authCalloutSub, err := authNC.Subscribe(authCalloutSubject, handler.HandleAuthRequest)
	if err != nil {
		logger.Fatal("Failed to subscribe to auth callout", zap.Error(err))
	}
	defer func() { _ = authCalloutSub.Unsubscribe() }()

	logger.Debug("Subscribed to", zap.String("subject", authCalloutSubject))

	logger.Info("===========================================")
	logger.Info("Auth callout service is now running!")
	logger.Info("===========================================")
	logger.Info("The service will authorize incoming connections.")
	logger.Info("Press Ctrl+C to exit...")

	select {}
}

// initAuthorizer creates the auth backend based on configuration
func initAuthorizer(ctx context.Context, backend, jwksURL, jwksPath, jwtIssuer, jwtAudience string, logger *zap.Logger) auth.Authorizer {
	switch backend {
	case "k8s-oidc":
		return initK8sOIDCAuthorizer(ctx, jwksURL, jwksPath, jwtIssuer, jwtAudience, logger)
	case "allow-all":
		logger.Info("Using allow-all auth backend (all connections authorized)")
		return &auth.AllowAllAuthorizer{}
	default:
		logger.Fatal("Unknown auth backend", zap.String("backend", backend))
		return nil
	}
}

func initK8sOIDCAuthorizer(ctx context.Context, jwksURL, jwksPath, jwtIssuer, jwtAudience string, logger *zap.Logger) auth.Authorizer {
	logger.Info("Initializing K8s OIDC auth backend...")

	validator := initJWTValidator(jwksPath, jwksURL, jwtIssuer, jwtAudience, logger)
	k8sClient := initK8sClient(ctx, logger)

	return auth.NewK8sOIDCAuthorizer(validator, k8sClient)
}

func initJWTValidator(jwksPath, jwksURL, jwtIssuer, jwtAudience string, logger *zap.Logger) *jwtvalidator.Validator {
	var validator *jwtvalidator.Validator
	var err error

	if jwksPath != "" {
		validator, err = jwtvalidator.NewValidatorFromFile(jwksPath, jwtIssuer, jwtAudience)
	} else {
		validator, err = jwtvalidator.NewValidatorFromURL(jwksURL, jwtIssuer, jwtAudience)
	}

	if err != nil {
		logger.Fatal("Failed to initialize JWT validator", zap.Error(err))
	}
	logger.Debug("JWT validator initialized")
	return validator
}

func initK8sClient(ctx context.Context, logger *zap.Logger) *k8s.Client {
	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		logger.Fatal("Failed to get in-cluster K8s config", zap.Error(err))
	}
	clientset, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		logger.Fatal("Failed to create K8s clientset", zap.Error(err))
	}
	factory := informers.NewSharedInformerFactory(clientset, 0)
	k8sClient := k8s.NewClient(factory)
	k8sClient.Start(ctx)
	logger.Debug("K8s ServiceAccount cache initialized")
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
