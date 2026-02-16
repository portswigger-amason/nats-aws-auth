// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"context"
	"fmt"
	"os"

	flag "github.com/spf13/pflag"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

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

	// Logging flags
	var debug = flag.Bool("debug", false, "enable debug logging")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "This is a service that implements the callout authentication mechanism for NATS.\n")
		fmt.Fprintf(os.Stderr, "Please see the README for more information: https://github.com/portswigger/nats-aws-auth\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	// Initialize logger
	logger := initLogger(*debug)
	defer func() {
		_ = logger.Sync() // Ignore error on sync at program exit
	}()

	ctx := context.Background()

	if *generate {
		runGenerate(ctx, logger, *operatorName, *sysAccountName, *authAccountName, *region, *outputDir, *aliasPrefix)
	} else {
		authorizer := initAuthorizer(ctx, *authBackend, *jwksURL, *jwksPath, *jwtIssuer, *jwtAudience, logger)
		runAuthService(ctx, *authAccountName, *appAccountName, *region, *natsURL, authorizer, logger)
	}
}

func initLogger(debug bool) *zap.Logger {
	config := zap.NewProductionConfig()
	config.Encoding = "console"
	config.EncoderConfig.TimeKey = "time"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	if debug {
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	logger, err := config.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	return logger
}
