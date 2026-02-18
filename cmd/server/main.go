// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"context"
	"fmt"
	"log"
	"os"

	flag "github.com/spf13/pflag"
)

func main() {
	// Common flags
	var generate = flag.Bool("generate", false, "Generate a config file for nats-server to stdout and exit")
	var generateCreds = flag.Bool("generate-credentials", false, "Generate NACK credentials file and exit")
	var region = flag.String("region", "", "AWS region (uses AWS config/environment if not specified)")

	// Config generation mode flags
	var operatorName = flag.String("operator-name", "KMS-Operator", "operator name for generated configuration")
	var sysAccountName = flag.String("sys-account", "SYS", "system account name")
	var outputDir = flag.String("output", ".", "output directory for generated files")
	var aliasPrefix = flag.String("alias-prefix", "nats", "prefix for KMS key aliases")
	var appAccountKeyAlias = flag.String("app-account-key-alias", "", "KMS key alias for APP account (e.g. 'nats-app-account'). When set, uses a stable KMS-backed key for the APP account identity")

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

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "This is a service that implements the callout authentication mechanism for NATS.\n")
		fmt.Fprintf(os.Stderr, "Please see the README for more information: https://github.com/portswigger/nats-aws-auth\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	ctx := context.Background()

	if *generate {
		runGenerate(ctx, *operatorName, *sysAccountName, *authAccountName, *region, *outputDir, *aliasPrefix)
	} else if *generateCreds {
		if *appAccountKeyAlias == "" {
			log.Fatal("--app-account-key-alias is required for --generate-credentials")
		}
		runGenerateCredentials(ctx, *region, *appAccountKeyAlias, *outputDir)
	} else {
		authorizer := initAuthorizer(ctx, *authBackend, *jwksURL, *jwksPath, *jwtIssuer, *jwtAudience)
		runAuthService(ctx, *authAccountName, *appAccountName, *region, *natsURL, *appAccountKeyAlias, authorizer)
	}
}
