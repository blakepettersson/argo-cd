package repository

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// CodeCommitAuthenticator generates Git credentials for AWS CodeCommit
// using AWS STS credentials via the GRC (Git Remote CodeCommit) signing process.
//
// AWS CodeCommit supports two authentication methods for HTTPS:
// 1. Static Git credentials (IAM user-based, not suitable for workload identity)
// 2. Signed credentials using AWS SigV4 (what this authenticator implements)
//
// This authenticator generates a signed password that encodes the AWS credentials
// and can be used with any Git client over HTTPS.
type CodeCommitAuthenticator struct{}

// NewCodeCommitAuthenticator creates a new CodeCommit authenticator
func NewCodeCommitAuthenticator() *CodeCommitAuthenticator {
	return &CodeCommitAuthenticator{}
}

// Authenticate generates Git credentials for AWS CodeCommit
func (a *CodeCommitAuthenticator) Authenticate(ctx context.Context, token *Token, repoURL string, cfg *Config) (*Credentials, error) {
	if token.Type != TokenTypeAWS {
		return nil, fmt.Errorf("codecommit authenticator requires AWS credentials, got %s", token.Type)
	}

	if token.AWSCredentials == nil {
		return nil, fmt.Errorf("AWS credentials are nil")
	}

	region := extractCodeCommitRegion(repoURL)
	if region == "" {
		region = token.AWSCredentials.Region
	}

	// Extract the path from the URL (e.g., /v1/repos/my-repo)
	repoPath := extractCodeCommitPath(repoURL)

	log.WithFields(log.Fields{
		"region":   region,
		"repoURL":  repoURL,
		"repoPath": repoPath,
	}).Info("CodeCommit: generating signed Git credentials")

	// Generate signed credentials using AWS SigV4
	// This implements the GRC (Git Remote CodeCommit) credential helper protocol
	username, password, err := a.generateSignedCredentials(
		token.AWSCredentials.AccessKeyID,
		token.AWSCredentials.SecretAccessKey,
		token.AWSCredentials.SessionToken,
		region,
		repoPath,
	)
	if err != nil {
		log.WithError(err).Error("CodeCommit: failed to generate signed credentials")
		return nil, fmt.Errorf("failed to generate CodeCommit credentials: %w", err)
	}

	log.WithField("region", region).Info("CodeCommit: successfully generated Git credentials")

	return &Credentials{
		Username: username,
		Password: password,
	}, nil
}

// generateSignedCredentials creates signed Git credentials for CodeCommit HTTPS authentication.
// This implements the same signing process used by git-remote-codecommit.
//
// The credential format is:
// - Username: AccessKeyID + "%" + SessionToken (URL-encoded)
// - Password: timestamp + "Z" + signature
func (a *CodeCommitAuthenticator) generateSignedCredentials(accessKeyID, secretAccessKey, sessionToken, region, repoPath string) (username, password string, err error) {
	// Use current time for signing
	now := time.Now().UTC()
	dateStamp := now.Format("20060102")
	timestamp := now.Format("20060102T150405")

	// Service and host for CodeCommit
	service := "codecommit"
	host := fmt.Sprintf("git-codecommit.%s.amazonaws.com", region)

	// Create the credential scope
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)

	// Create the canonical request
	// Format: METHOD\nPATH\nQUERY\nHEADERS\n\nSIGNED_HEADERS\n
	// CodeCommit doesn't support query parameters or a payload, so omit both
	canonicalRequest := fmt.Sprintf("GIT\n%s\n\nhost:%s\n\nhost\n", repoPath, host)
	canonicalRequestHash := sha256Hash(canonicalRequest)

	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		timestamp,
		credentialScope,
		canonicalRequestHash,
	)

	// Calculate the signing key
	signingKey := a.getSignatureKey(secretAccessKey, dateStamp, region, service)

	// Calculate the signature
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	// Build credentials
	// Username: AccessKeyID%SessionToken (URL-encoded)
	// Password: timestampZsignature
	if sessionToken != "" {
		username = url.QueryEscape(accessKeyID + "%" + sessionToken)
	} else {
		username = url.QueryEscape(accessKeyID)
	}
	password = timestamp + "Z" + signature

	return username, password, nil
}

// getSignatureKey derives the signing key using AWS SigV4 key derivation
func (a *CodeCommitAuthenticator) getSignatureKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}

// hmacSHA256 calculates HMAC-SHA256
func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// sha256Hash calculates SHA256 hash and returns hex-encoded string
func sha256Hash(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// extractCodeCommitRegion extracts the AWS region from a CodeCommit repository URL
// Example: https://git-codecommit.us-west-2.amazonaws.com/v1/repos/my-repo → us-west-2
func extractCodeCommitRegion(repoURL string) string {
	// Remove scheme
	repoURL = strings.TrimPrefix(repoURL, "https://")
	repoURL = strings.TrimPrefix(repoURL, "http://")

	// Check if it's a CodeCommit URL
	if strings.HasPrefix(repoURL, "git-codecommit.") {
		// Format: git-codecommit.REGION.amazonaws.com/...
		parts := strings.Split(repoURL, ".")
		if len(parts) >= 2 {
			return parts[1]
		}
	}

	return ""
}

// extractCodeCommitPath extracts the path from a CodeCommit repository URL
// Example: https://git-codecommit.us-west-2.amazonaws.com/v1/repos/my-repo → /v1/repos/my-repo
func extractCodeCommitPath(repoURL string) string {
	parsed, err := url.Parse(repoURL)
	if err != nil {
		// Fallback: try to extract path manually
		repoURL = strings.TrimPrefix(repoURL, "https://")
		repoURL = strings.TrimPrefix(repoURL, "http://")
		if idx := strings.Index(repoURL, "/"); idx != -1 {
			return repoURL[idx:]
		}
		return "/"
	}
	if parsed.Path == "" {
		return "/"
	}
	return parsed.Path
}

// Ensure CodeCommitAuthenticator implements Authenticator
var _ Authenticator = (*CodeCommitAuthenticator)(nil)