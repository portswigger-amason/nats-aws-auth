// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func TestCreateNackUserClaims(t *testing.T) {
	// Create a local account keypair to act as the APP account (stands in for KMS in tests)
	accountKP, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("failed to create account keypair: %v", err)
	}
	accountPubKey, _ := accountKP.PublicKey()

	userKP, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("failed to create user keypair: %v", err)
	}
	userPubKey, _ := userKP.PublicKey()

	claims := createNackUserClaims(userPubKey, accountPubKey)

	// Verify basic fields
	if claims.Name != "nack" {
		t.Errorf("expected name 'nack', got %q", claims.Name)
	}
	if claims.IssuerAccount != accountPubKey {
		t.Errorf("expected issuer account %s, got %s", accountPubKey, claims.IssuerAccount)
	}
	if claims.Subject != userPubKey {
		t.Errorf("expected subject %s, got %s", userPubKey, claims.Subject)
	}

	// Verify JetStream API permissions
	expectedPub := []string{"$JS.API.>"}
	expectedSub := []string{"$JS.API.>", "_INBOX.>"}

	if len(claims.Pub.Allow) != len(expectedPub) {
		t.Fatalf("expected %d pub allows, got %d", len(expectedPub), len(claims.Pub.Allow))
	}
	for i, v := range expectedPub {
		if string(claims.Pub.Allow[i]) != v {
			t.Errorf("pub allow[%d]: expected %q, got %q", i, v, claims.Pub.Allow[i])
		}
	}

	if len(claims.Sub.Allow) != len(expectedSub) {
		t.Fatalf("expected %d sub allows, got %d", len(expectedSub), len(claims.Sub.Allow))
	}
	for i, v := range expectedSub {
		if string(claims.Sub.Allow[i]) != v {
			t.Errorf("sub allow[%d]: expected %q, got %q", i, v, claims.Sub.Allow[i])
		}
	}
}

func TestCreateNackUserClaims_CanEncode(t *testing.T) {
	accountKP, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("failed to create account keypair: %v", err)
	}
	accountPubKey, err := accountKP.PublicKey()
	if err != nil {
		t.Fatalf("failed to get account public key: %v", err)
	}
	userKP, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("failed to create user keypair: %v", err)
	}
	userPubKey, err := userKP.PublicKey()
	if err != nil {
		t.Fatalf("failed to get user public key: %v", err)
	}

	claims := createNackUserClaims(userPubKey, accountPubKey)

	// Encode with the account keypair (simulates what KMS signing does)
	token, err := claims.Encode(accountKP)
	if err != nil {
		t.Fatalf("failed to encode claims: %v", err)
	}

	// Decode and verify round-trip
	decoded, err := jwt.DecodeUserClaims(token)
	if err != nil {
		t.Fatalf("failed to decode token: %v", err)
	}
	if decoded.Name != "nack" {
		t.Errorf("decoded name: expected 'nack', got %q", decoded.Name)
	}
	if decoded.IssuerAccount != accountPubKey {
		t.Errorf("decoded issuer account mismatch")
	}
}

func TestFormatCredentials(t *testing.T) {
	result := formatCredentials("eyJhbGciOiJFZDI1NTE5In0.test", "SUAM_test_seed")

	// Check structure markers
	if !strings.Contains(result, "-----BEGIN NATS USER JWT-----") {
		t.Error("missing JWT begin marker")
	}
	if !strings.Contains(result, "------END NATS USER JWT------") {
		t.Error("missing JWT end marker")
	}
	if !strings.Contains(result, "-----BEGIN USER NKEY SEED-----") {
		t.Error("missing seed begin marker")
	}
	if !strings.Contains(result, "------END USER NKEY SEED------") {
		t.Error("missing seed end marker")
	}
	if !strings.Contains(result, "eyJhbGciOiJFZDI1NTE5In0.test") {
		t.Error("JWT not found in output")
	}
	if !strings.Contains(result, "SUAM_test_seed") {
		t.Error("seed not found in output")
	}
}
