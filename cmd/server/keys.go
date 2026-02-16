// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// ==========================================
// Type Definitions
// ==========================================

// KMSKey holds information about a KMS-backed key
type KMSKey struct {
	KeyID     string
	PublicKey string // nkey-formatted public key
	RawPubKey []byte // raw 32-byte Ed25519 public key
}

// LocalKey holds information about a locally generated key
type LocalKey struct {
	Seed      string // nkey seed (private key)
	PublicKey string // nkey-formatted public key
	KeyPair   nkeys.KeyPair
}

// dummyKeyPair implements nkeys.KeyPair interface for KMS-backed keys
type dummyKeyPair struct {
	pubKey string
}

func (d *dummyKeyPair) Seed() ([]byte, error) {
	return nil, fmt.Errorf("seed not available - key is stored in KMS")
}

func (d *dummyKeyPair) PublicKey() (string, error) {
	return d.pubKey, nil
}

func (d *dummyKeyPair) PrivateKey() ([]byte, error) {
	return nil, fmt.Errorf("private key not available - key is stored in KMS")
}

func (d *dummyKeyPair) Sign(input []byte) ([]byte, error) {
	return nil, fmt.Errorf("direct signing not available - use SignFn with KMS")
}

func (d *dummyKeyPair) Verify(input []byte, sig []byte) error {
	return fmt.Errorf("verify not implemented for dummy keypair")
}

func (d *dummyKeyPair) Wipe() {}

func (d *dummyKeyPair) Open(input []byte, sender string) ([]byte, error) {
	return nil, fmt.Errorf("open not available - key is stored in KMS")
}

func (d *dummyKeyPair) Seal(input []byte, recipient string) ([]byte, error) {
	return nil, fmt.Errorf("seal not available - key is stored in KMS")
}

func (d *dummyKeyPair) SealWithRand(input []byte, recipient string, rr io.Reader) ([]byte, error) {
	return nil, fmt.Errorf("seal not available - key is stored in KMS")
}

// ==========================================
// AWS and KMS Functions
// ==========================================

func loadAWSConfig(ctx context.Context, region string) (aws.Config, error) {
	if region != "" {
		return config.LoadDefaultConfig(ctx, config.WithRegion(region))
	}
	return config.LoadDefaultConfig(ctx)
}

// createKMSSigner creates a SignFn that signs using AWS KMS
func createKMSSigner(ctx context.Context, client *kms.Client, keyID string) jwt.SignFn {
	return func(pub string, data []byte) ([]byte, error) {
		// KMS has a 4096 byte limit for raw message signing with Ed25519
		if len(data) > 4096 {
			return nil, fmt.Errorf("message size (%d bytes) exceeds KMS limit of 4096 bytes", len(data))
		}

		signOutput, err := client.Sign(ctx, &kms.SignInput{
			KeyId:            aws.String(keyID),
			Message:          data,
			MessageType:      types.MessageTypeRaw,
			SigningAlgorithm: "ED25519_SHA_512",
		})
		if err != nil {
			return nil, fmt.Errorf("KMS sign failed: %w", err)
		}

		return signOutput.Signature, nil
	}
}

func extractEd25519PublicKey(derBytes []byte) ([]byte, error) {
	pubKeyInterface, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		block, _ := pem.Decode(derBytes)
		if block != nil {
			pubKeyInterface, err = x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse public key: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
	}

	switch pubKey := pubKeyInterface.(type) {
	case ed25519.PublicKey:
		if len(pubKey) != 32 {
			return nil, fmt.Errorf("invalid Ed25519 public key length: %d (expected 32)", len(pubKey))
		}
		return []byte(pubKey), nil
	default:
		return nil, fmt.Errorf("unexpected public key type: %T", pubKeyInterface)
	}
}

// getOrCreateKMSKey checks if a KMS key with the given alias exists and is the correct type.
// If it exists and is valid, it returns the existing key. Otherwise, it creates a new one.
func getOrCreateKMSKey(ctx context.Context, client *kms.Client, prefix nkeys.PrefixByte, alias string) (*KMSKey, bool, error) {
	aliasName := alias
	if !strings.HasPrefix(aliasName, "alias/") {
		aliasName = "alias/" + aliasName
	}

	// Try to get the existing key by alias
	existingKey, err := getExistingKMSKey(ctx, client, aliasName, prefix)
	if err == nil && existingKey != nil {
		// Key exists and is valid
		return existingKey, true, nil
	}

	// Key doesn't exist or is invalid, create a new one
	newKey, err := createKMSKey(ctx, client, prefix, aliasName)
	if err != nil {
		return nil, false, err
	}

	return newKey, false, nil
}

// getExistingKMSKey attempts to retrieve an existing KMS key by alias and validates its type
func getExistingKMSKey(ctx context.Context, client *kms.Client, aliasName string, prefix nkeys.PrefixByte) (*KMSKey, error) {
	// Try to describe the key using the alias
	describeOutput, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(aliasName),
	})
	if err != nil {
		// Key doesn't exist
		return nil, err
	}

	keyMetadata := describeOutput.KeyMetadata

	// Verify the key is enabled
	if keyMetadata.KeyState != types.KeyStateEnabled {
		return nil, fmt.Errorf("key %s exists but is not enabled (state: %s)", aliasName, keyMetadata.KeyState)
	}

	// Verify it's an Ed25519 key
	if keyMetadata.KeySpec != types.KeySpecEccNistEdwards25519 {
		return nil, fmt.Errorf("key %s exists but is not Ed25519 (spec: %s)", aliasName, keyMetadata.KeySpec)
	}

	// Verify it's a sign/verify key
	if keyMetadata.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("key %s exists but is not for signing (usage: %s)", aliasName, keyMetadata.KeyUsage)
	}

	keyID := *keyMetadata.KeyId

	// Get the public key
	getPublicKeyOutput, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from KMS: %w", err)
	}

	// Extract the raw Ed25519 public key
	rawPubKey, err := extractEd25519PublicKey(getPublicKeyOutput.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract Ed25519 public key: %w", err)
	}

	// Encode the public key in nkey format
	nkeyPublic, err := nkeys.Encode(prefix, rawPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key in nkey format: %w", err)
	}

	return &KMSKey{
		KeyID:     keyID,
		PublicKey: string(nkeyPublic),
		RawPubKey: rawPubKey,
	}, nil
}

// createKMSKey creates a new KMS key with the given alias
func createKMSKey(ctx context.Context, client *kms.Client, prefix nkeys.PrefixByte, aliasName string) (*KMSKey, error) {
	// Create the KMS asymmetric key with Ed25519
	createKeyInput := &kms.CreateKeyInput{
		KeySpec:     "ECC_NIST_EDWARDS25519",
		KeyUsage:    types.KeyUsageTypeSignVerify,
		Description: aws.String(fmt.Sprintf("NATS %s key", prefix.String())),
	}

	createKeyOutput, err := client.CreateKey(ctx, createKeyInput)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS key: %w", err)
	}

	keyID := *createKeyOutput.KeyMetadata.KeyId

	// Create alias if provided
	if aliasName != "" {
		if !strings.HasPrefix(aliasName, "alias/") {
			aliasName = "alias/" + aliasName
		}
		_, err = client.CreateAlias(ctx, &kms.CreateAliasInput{
			AliasName:   aws.String(aliasName),
			TargetKeyId: aws.String(keyID),
		})
		if err != nil {
			log.Printf("Warning: failed to create alias %s: %v", aliasName, err)
		}
	}

	// Get the public key from KMS
	getPublicKeyOutput, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from KMS: %w", err)
	}

	// Extract the raw Ed25519 public key
	rawPubKey, err := extractEd25519PublicKey(getPublicKeyOutput.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract Ed25519 public key: %w", err)
	}

	// Encode the public key in nkey format
	nkeyPublic, err := nkeys.Encode(prefix, rawPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key in nkey format: %w", err)
	}

	return &KMSKey{
		KeyID:     keyID,
		PublicKey: string(nkeyPublic),
		RawPubKey: rawPubKey,
	}, nil
}

func createLocalKey(prefix nkeys.PrefixByte) (*LocalKey, error) {
	var kp nkeys.KeyPair
	var err error

	switch prefix {
	case nkeys.PrefixByteAccount:
		kp, err = nkeys.CreateAccount()
	case nkeys.PrefixByteUser:
		kp, err = nkeys.CreateUser()
	case nkeys.PrefixByteOperator:
		kp, err = nkeys.CreateOperator()
	default:
		return nil, fmt.Errorf("unsupported key prefix: %v", prefix)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create keypair: %w", err)
	}

	seed, err := kp.Seed()
	if err != nil {
		return nil, fmt.Errorf("failed to get seed: %w", err)
	}

	pubKey, err := kp.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	return &LocalKey{
		Seed:      string(seed),
		PublicKey: pubKey,
		KeyPair:   kp,
	}, nil
}
