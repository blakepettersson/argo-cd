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
// ## Authentication Methods
//
// This implementation supports two authentication methods, tried in order:
//
// 1. **EKS Pod Identity** (preferred): If the Pod Identity Agent is available
//    (detected via AWS_CONTAINER_CREDENTIALS_FULL_URI env var), requests a K8s token
//    with audience "pods.eks.amazonaws.com" and exchanges it via the agent's HTTP endpoint.
//    Setup: `aws eks create-pod-identity-association` per service account — no OIDC provider needed.
//
// 2. **IRSA** (fallback): Exchanges a K8s token via STS AssumeRoleWithWebIdentity.
//    Requires OIDC provider + IAM trust policy per service account (setup documented above).
//
// Both methods support ArgoCD's multi-tenant model where a single repo-server pod
// assumes different IAM roles per project by requesting tokens for per-project service accounts
// via the TokenRequest API.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/repository"
)

const (
	// AnnotationAWSRoleARN is the EKS annotation for IAM role
	AnnotationAWSRoleARN = "eks.amazonaws.com/role-arn"

	// DefaultAWSAudience is the default STS audience for IRSA
	DefaultAWSAudience = "sts.amazonaws.com"

	// PodIdentityAudience is the audience for EKS Pod Identity tokens
	PodIdentityAudience = "pods.eks.amazonaws.com"

	// EnvPodIdentityAgentURI is set by the Pod Identity webhook when the agent is available
	EnvPodIdentityAgentURI = "AWS_CONTAINER_CREDENTIALS_FULL_URI"
)

// AWSProvider exchanges K8s JWTs for AWS credentials via STS
type AWSProvider struct {
	repo *v1alpha1.Repository
	k8s  *K8sProvider
}

func (p *AWSProvider) DefaultRepositoryAuthenticator() repository.Authenticator {
	return repository.NewECRAuthenticator()
}

// NewAWSProvider creates a new AWS identity provider
func NewAWSProvider(repo *v1alpha1.Repository, k8s *K8sProvider) *AWSProvider {
	return &AWSProvider{
		repo: repo,
		k8s:  k8s,
	}
}

// GetToken exchanges a K8s JWT for AWS credentials.
// It tries EKS Pod Identity first (if the agent is available), then falls back to IRSA.
func (p *AWSProvider) GetToken(ctx context.Context, audience string, tokenURL string) (*repository.Token, error) {
	saName := p.k8s.sa.Name
	// ECR region is derived from the repository URL — this is the region the ECR
	// authenticator needs for GetAuthorizationToken, independent of where STS runs.
	ecrRegion := extractAWSRegion(p.repo.Repo)

	// Try EKS Pod Identity first
	if agentURI := os.Getenv(EnvPodIdentityAgentURI); agentURI != "" {
		token, err := p.getTokenViaPodIdentity(ctx, agentURI, ecrRegion)
		if err != nil {
			log.WithFields(log.Fields{
				"serviceAccount": saName,
				"error":          err.Error(),
			}).Warn("AWS Pod Identity: failed, falling back to IRSA")
		} else {
			return token, nil
		}
	}

	return p.getTokenViaIRSA(ctx, audience, tokenURL, ecrRegion)
}

// getTokenViaPodIdentity exchanges a K8s token via the EKS Pod Identity Agent HTTP endpoint.
func (p *AWSProvider) getTokenViaPodIdentity(ctx context.Context, agentURI string, region string) (*repository.Token, error) {
	saName := p.k8s.sa.Name

	// Request K8s token with Pod Identity audience
	k8sToken, err := p.k8s.GetToken(ctx, PodIdentityAudience, "")
	if err != nil {
		return nil, fmt.Errorf("failed to request K8s token: %w", err)
	}

	log.WithFields(log.Fields{
		"serviceAccount": saName,
		"agentURI":       agentURI,
	}).Info("AWS Pod Identity: exchanging token via agent")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, agentURI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", k8sToken.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pod identity agent request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read agent response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pod identity agent returned %d: %s", resp.StatusCode, string(body))
	}

	// The agent returns the standard container credentials JSON format
	var creds podIdentityCredentials
	if err := json.Unmarshal(body, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse agent response: %w", err)
	}

	log.WithFields(log.Fields{
		"serviceAccount": saName,
		"expiration":     creds.Expiration,
	}).Info("AWS Pod Identity: successfully obtained credentials")

	return &repository.Token{
		Type: repository.TokenTypeAWS,
		AWSCredentials: &repository.AWSCredentials{
			AccessKeyID:     creds.AccessKeyID,
			SecretAccessKey: creds.SecretAccessKey,
			SessionToken:    creds.Token,
			Region:          region,
		},
	}, nil
}

// podIdentityCredentials is the JSON response from the Pod Identity Agent endpoint.
type podIdentityCredentials struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

// getTokenViaIRSA exchanges a K8s token for AWS credentials via STS AssumeRoleWithWebIdentity.
// The SDK resolves its own region for STS (from AWS_REGION/AWS_DEFAULT_REGION injected by the
// EKS webhook). ecrRegion is only used in the returned credentials for ECR GetAuthorizationToken.
func (p *AWSProvider) getTokenViaIRSA(ctx context.Context, audience string, tokenURL string, ecrRegion string) (*repository.Token, error) {
	saName := p.k8s.sa.Name
	roleARN := p.k8s.sa.Annotations[AnnotationAWSRoleARN]
	if roleARN == "" {
		return nil, fmt.Errorf("service account %s missing %s annotation", saName, AnnotationAWSRoleARN)
	}

	if audience == "" {
		audience = DefaultAWSAudience
	}

	k8sToken, err := p.k8s.GetToken(ctx, audience, "")
	if err != nil {
		return nil, fmt.Errorf("failed to request K8s token: %w", err)
	}

	// Let the SDK resolve region from env (AWS_REGION/AWS_DEFAULT_REGION injected by EKS webhook)
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	log.WithFields(log.Fields{
		"serviceAccount": saName,
		"roleARN":        roleARN,
		"stsRegion":      awsCfg.Region,
		"ecrRegion":      ecrRegion,
	}).Info("AWS IRSA: assuming IAM role with web identity")

	stsEndpoint := tokenURL
	if stsEndpoint != "" {
		log.WithField("stsEndpoint", stsEndpoint).Debug("AWS IRSA: using custom STS endpoint")
	}

	var stsOpts []func(*sts.Options)
	if stsEndpoint != "" {
		stsOpts = append(stsOpts, func(o *sts.Options) {
			o.BaseEndpoint = aws.String(stsEndpoint)
		})
	}
	stsClient := sts.NewFromConfig(awsCfg, stsOpts...)

	roleSessionName := "argocd-" + saName
	durationSeconds := int32(3600)
	log.WithFields(log.Fields{
		"roleSessionName": roleSessionName,
	}).Debug("AWS IRSA: calling STS AssumeRoleWithWebIdentity")

	assumeResult, err := stsClient.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleARN),
		WebIdentityToken: aws.String(k8sToken.Token),
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
			Region:          ecrRegion,
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
