package identity

// # AWS IRSA (IAM Roles for Service Accounts) Setup
//
// This file implements AWS IRSA for authenticating to AWS Elastic Container Registry (ECR)
// using Kubernetes service account tokens.
//
// ## Required AWS/EKS Setup
//
// 1. Ensure your EKS cluster has an OIDC provider configured:
//
//	export CLUSTER_NAME="<your-cluster-name>"
//	export AWS_REGION="<your-region>"
//
//	# Check if OIDC provider exists
//	aws eks describe-cluster --name $CLUSTER_NAME --query "cluster.identity.oidc.issuer" --output text
//
//	# If not set up, create the OIDC provider
//	eksctl utils associate-iam-oidc-provider --cluster $CLUSTER_NAME --approve
//
// 2. Get the OIDC provider URL and account ID:
//
//	export OIDC_PROVIDER=$(aws eks describe-cluster --name $CLUSTER_NAME \
//	    --query "cluster.identity.oidc.issuer" --output text | sed -e "s/^https:\/\///")
//	export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
//
// 3. Create an IAM policy for ECR access:
//
//	cat <<EOF > ecr-policy.json
//	{
//	    "Version": "2012-10-17",
//	    "Statement": [
//	        {
//	            "Effect": "Allow",
//	            "Action": [
//	                "ecr:GetAuthorizationToken",
//	                "ecr:BatchCheckLayerAvailability",
//	                "ecr:GetDownloadUrlForLayer",
//	                "ecr:BatchGetImage"
//	            ],
//	            "Resource": "*"
//	        }
//	    ]
//	}
//	EOF
//	aws iam create-policy --policy-name ArgoCD-ECR-ReadOnly --policy-document file://ecr-policy.json
//
// 4. Create an IAM role with trust policy for the ArgoCD service account:
//
//	export ARGOCD_NAMESPACE="argocd"
//	export PROJECT_NAME="default"
//	export ROLE_NAME="argocd-project-${PROJECT_NAME}"
//
//	cat <<EOF > trust-policy.json
//	{
//	    "Version": "2012-10-17",
//	    "Statement": [
//	        {
//	            "Effect": "Allow",
//	            "Principal": {
//	                "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
//	            },
//	            "Action": "sts:AssumeRoleWithWebIdentity",
//	            "Condition": {
//	                "StringEquals": {
//	                    "${OIDC_PROVIDER}:sub": "system:serviceaccount:${ARGOCD_NAMESPACE}:argocd-project-${PROJECT_NAME}",
//	                    "${OIDC_PROVIDER}:aud": "sts.amazonaws.com"
//	                }
//	            }
//	        }
//	    ]
//	}
//	EOF
//
//	aws iam create-role --role-name $ROLE_NAME --assume-role-policy-document file://trust-policy.json
//	aws iam attach-role-policy --role-name $ROLE_NAME \
//	    --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/ArgoCD-ECR-ReadOnly
//
// ## Required Kubernetes ServiceAccount Annotations
//
// The Kubernetes ServiceAccount (argocd-project-<name>) needs this annotation:
//
//   - eks.amazonaws.com/role-arn: The full ARN of the IAM role to assume
//     Example: arn:aws:iam::123456789012:role/argocd-project-default
//
// ## Required Repository Secret Fields
//
//   - useWorkloadIdentity: "true"
//   - workloadIdentityProvider: "aws"
//   - project: "<argocd-project-name>" (maps to argocd-project-<name> ServiceAccount)
//
// ## Optional Configuration
//
//   - workloadIdentityTokenURL: Override STS endpoint (for GovCloud, China regions, etc.)
//     Example for GovCloud: "https://sts.us-gov-west-1.amazonaws.com"
//
// ## Authentication Flow
//
// 1. Request a K8s token for the project ServiceAccount via TokenRequest API
//    (with audience "sts.amazonaws.com")
// 2. Call AWS STS AssumeRoleWithWebIdentity with the K8s token
// 3. Use the temporary credentials to call ECR GetAuthorizationToken
// 4. Return the ECR credentials for use with the registry
//
// ## Region Detection
//
// The AWS region is automatically extracted from the ECR repository URL.
// Example: 123456789012.dkr.ecr.us-west-2.amazonaws.com → us-west-2
//
// ## Note on EKS Pod Identity
//
// This implementation uses IRSA (IAM Roles for Service Accounts) rather than the newer
// EKS Pod Identity feature. While EKS Pod Identity is simpler to set up for single-identity
// workloads, IRSA is required for ArgoCD's multi-tenant workload identity model because:
//
//   - ArgoCD needs to assume different IAM roles per project from a single repo-server pod
//   - IRSA allows exchanging any service account token via STS AssumeRoleWithWebIdentity
//   - EKS Pod Identity injects credentials at pod startup for only the pod's own service account
//
// IRSA and EKS Pod Identity coexist on the same cluster - you can use Pod Identity for other
// workloads while using IRSA for ArgoCD's workload identity feature.

import (
	"context"
	"fmt"
	"strings"

	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/repository"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

const (
	// AnnotationAWSRoleARN is the EKS annotation for IAM role
	AnnotationAWSRoleARN = "eks.amazonaws.com/role-arn"

	// DefaultAWSAudience is the default STS audience
	DefaultAWSAudience = "sts.amazonaws.com"
)

// AWSProvider exchanges K8s JWTs for AWS credentials via STS
type AWSProvider struct {
	repo *v1alpha1.Repository
}

func (p *AWSProvider) DefaultRepositoryAuthenticator() repository.Authenticator {
	if p.repo.Type == "git" {
		return repository.NewCodeCommitAuthenticator()
	}
	return repository.NewECRAuthenticator()
}

// NewAWSProvider creates a new AWS identity provider
func NewAWSProvider(repo *v1alpha1.Repository) *AWSProvider {
	return &AWSProvider{
		repo: repo,
	}
}

// GetToken exchanges a K8s JWT for AWS credentials
func (p *AWSProvider) GetToken(ctx context.Context, sa *corev1.ServiceAccount, requestToken TokenRequester, cfg *Config) (*repository.Token, error) {
	// Get role ARN from standard EKS annotation on service account
	roleARN := sa.Annotations[AnnotationAWSRoleARN]
	if roleARN == "" {
		return nil, fmt.Errorf("service account %s missing %s annotation", sa.Name, AnnotationAWSRoleARN)
	}

	// Use configured audience or default to STS
	audience := cfg.Audience
	if audience == "" {
		audience = DefaultAWSAudience
	}

	// Request K8s token with STS audience
	k8sToken, err := requestToken(ctx, audience)
	if err != nil {
		return nil, fmt.Errorf("failed to request K8s token: %w", err)
	}

	// Extract AWS region from ECR repository URL
	region := extractAWSRegion(p.repo.Repo)

	log.WithFields(log.Fields{
		"serviceAccount": sa.Name,
		"roleARN":        roleARN,
		"region":         region,
	}).Info("AWS IRSA: assuming IAM role with web identity")

	// Check for optional STS endpoint override (for GovCloud, China, etc.) from repository config
	stsEndpoint := cfg.TokenURL
	if stsEndpoint != "" {
		log.WithField("stsEndpoint", stsEndpoint).Debug("AWS IRSA: using custom STS endpoint")
	}

	// Load AWS config with region
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create STS client with optional endpoint override
	var stsOpts []func(*sts.Options)
	if stsEndpoint != "" {
		stsOpts = append(stsOpts, func(o *sts.Options) {
			o.BaseEndpoint = aws.String(stsEndpoint)
		})
	}
	stsClient := sts.NewFromConfig(awsCfg, stsOpts...)

	// Assume role with web identity using the K8s JWT
	roleSessionName := fmt.Sprintf("argocd-%s", sa.Name)
	durationSeconds := int32(3600)
	log.WithFields(log.Fields{
		"roleSessionName": roleSessionName,
	}).Debug("AWS IRSA: calling STS AssumeRoleWithWebIdentity")

	assumeResult, err := stsClient.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleARN),
		WebIdentityToken: aws.String(k8sToken),
		RoleSessionName:  aws.String(roleSessionName),
		DurationSeconds:  &durationSeconds,
	})
	if err != nil {
		log.WithFields(log.Fields{
			"roleARN": roleARN,
			"error":   err.Error(),
		}).Error("AWS IRSA: failed to assume role")
		return nil, fmt.Errorf("failed to assume role %s: %w", roleARN, err)
	}

	log.WithFields(log.Fields{
		"roleARN":    roleARN,
		"expiration": assumeResult.Credentials.Expiration,
	}).Info("AWS IRSA: successfully assumed IAM role")

	return &repository.Token{
		Type: repository.TokenTypeAWS,
		AWSCredentials: &repository.AWSCredentials{
			AccessKeyID:     *assumeResult.Credentials.AccessKeyId,
			SecretAccessKey: *assumeResult.Credentials.SecretAccessKey,
			SessionToken:    *assumeResult.Credentials.SessionToken,
			Expiration:      assumeResult.Credentials.Expiration,
			Region:          awsCfg.Region,
		},
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

// Ensure AWSProvider implements Provider
var _ Provider = (*AWSProvider)(nil)
