package workloadidentity

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/sts"
	corev1 "k8s.io/api/core/v1"
)

// resolveAWS resolves AWS ECR credentials using IRSA (IAM Roles for Service Accounts)
func (r *Resolver) resolveAWS(ctx context.Context, sa *corev1.ServiceAccount, k8sToken, repoURL string, config *ProviderConfig) (*Credentials, error) {
	// Get role ARN from standard EKS annotation on service account
	roleARN := sa.Annotations[AnnotationAWSRoleARN]
	if roleARN == "" {
		return nil, fmt.Errorf("service account %s missing %s annotation", sa.Name, AnnotationAWSRoleARN)
	}

	// Extract AWS region from ECR repository URL
	region := extractAWSRegion(repoURL)

	// Check for optional STS endpoint override (for GovCloud, China, etc.) from repository config
	endpoint := config.TokenURL

	// Create STS client configuration
	awsConfig := &aws.Config{
		Region: aws.String(region),
	}
	if endpoint != "" {
		awsConfig.Endpoint = aws.String(endpoint)
	}

	// Create STS session
	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}
	stsClient := sts.New(sess)

	// Assume role with web identity using the K8s JWT
	roleSessionName := fmt.Sprintf("argocd-%s", sa.Name)
	assumeResult, err := stsClient.AssumeRoleWithWebIdentityWithContext(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleARN),
		WebIdentityToken: aws.String(k8sToken),
		RoleSessionName:  aws.String(roleSessionName),
		DurationSeconds:  aws.Int64(3600),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to assume role %s: %w", roleARN, err)
	}

	// Create ECR client with temporary credentials from STS
	creds := credentials.NewStaticCredentials(
		*assumeResult.Credentials.AccessKeyId,
		*assumeResult.Credentials.SecretAccessKey,
		*assumeResult.Credentials.SessionToken,
	)

	ecrSess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: creds,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create ECR session: %w", err)
	}
	ecrClient := ecr.New(ecrSess)

	// Get ECR authorization token
	authResult, err := ecrClient.GetAuthorizationTokenWithContext(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ECR authorization token: %w", err)
	}

	if len(authResult.AuthorizationData) == 0 {
		return nil, fmt.Errorf("no ECR authorization data returned")
	}

	// Decode the base64-encoded authorization token
	decoded, err := base64.StdEncoding.DecodeString(*authResult.AuthorizationData[0].AuthorizationToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ECR authorization token: %w", err)
	}

	// ECR token format is "username:password"
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid ECR authorization token format")
	}

	return &Credentials{
		Username: parts[0],
		Password: parts[1],
	}, nil
}

// extractAWSRegion extracts the AWS region from an ECR repository URL
// Example: 123456789012.dkr.ecr.us-west-2.amazonaws.com → us-west-2
func extractAWSRegion(repoURL string) string {
	// Remove oci:// prefix if present
	repoURL = strings.TrimPrefix(repoURL, "oci://")

	// Split by dots: ["123456789012", "dkr", "ecr", "us-west-2", "amazonaws", "com"]
	parts := strings.Split(repoURL, ".")
	if len(parts) >= 4 && parts[1] == "dkr" && parts[2] == "ecr" {
		return parts[3]
	}

	// Default to us-east-1 if we can't parse the region
	return "us-east-1"
}