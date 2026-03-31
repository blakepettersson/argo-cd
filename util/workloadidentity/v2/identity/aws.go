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
// 1. **EKS Pod Identity** (preferred): Uses the EKS Auth API (AssumeRoleForPodIdentity)
//    to exchange a K8s token for AWS credentials. The cluster name is resolved from
//    ARGOCD_AWS_EKS_CLUSTER env var, or auto-detected via EC2 instance metadata (IMDS)
//    by parsing the EKS bootstrap script from user-data.
//    Setup: `aws eks create-pod-identity-association` per service account — no OIDC provider needed.
//
// 2. **IRSA** (fallback): Exchanges a K8s token via STS AssumeRoleWithWebIdentity.
//    Requires OIDC provider + IAM trust policy per service account (setup documented above).
//
// Both methods support ArgoCD's multi-tenant model where a single server pod
// assumes different IAM roles per project by requesting tokens for per-project service accounts
// via the TokenRequest API.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/eksauth"
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

	// EnvEKSCluster is the env var to explicitly set the EKS cluster name for Pod Identity
	EnvEKSCluster = "ARGOCD_AWS_EKS_CLUSTER"

	// EnvPodIdentityAgentURI is set by the Pod Identity webhook when the agent is available
	EnvPodIdentityAgentURI = "AWS_CONTAINER_CREDENTIALS_FULL_URI"

	// imdsTokenEndpoint is the IMDSv2 token endpoint
	imdsTokenEndpoint = "http://169.254.169.254/latest/api/token"

	// imdsUserDataEndpoint is the IMDS user-data endpoint
	imdsUserDataEndpoint = "http://169.254.169.254/latest/user-data"
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
// It tries EKS Pod Identity (via AssumeRoleForPodIdentity API) first, then falls back to IRSA.
func (p *AWSProvider) GetToken(ctx context.Context, audience string, tokenURL string) (*repository.Token, error) {
	saName := p.k8s.sa.Name
	// ECR region is derived from the repository URL — this is the region the ECR
	// authenticator needs for GetAuthorizationToken, independent of where STS runs.
	ecrRegion := extractAWSRegion(p.repo.Repo)

	// Try EKS Pod Identity via AssumeRoleForPodIdentity API
	if clusterName := p.resolveEKSClusterName(ctx); clusterName != "" {
		token, err := p.getTokenViaPodIdentity(ctx, clusterName, ecrRegion)
		if err != nil {
			log.WithFields(log.Fields{
				"serviceAccount": saName,
				"clusterName":    clusterName,
				"error":          err.Error(),
			}).Warn("AWS Pod Identity: failed, falling back to IRSA")
		} else {
			return token, nil
		}
	}

	return p.getTokenViaIRSA(ctx, audience, tokenURL, ecrRegion)
}

// resolveEKSClusterName returns the EKS cluster name from env var or IMDS user-data.
// Returns empty string if the cluster name cannot be determined.
func (p *AWSProvider) resolveEKSClusterName(ctx context.Context) string {
	// 1. Explicit env var
	if name := os.Getenv(EnvEKSCluster); name != "" {
		log.WithField("clusterName", name).Debug("AWS Pod Identity: cluster name from env var")
		return name
	}

	// 2. Auto-detect from EC2 instance metadata (IMDS) user-data
	name, err := getClusterNameFromIMDS(ctx)
	if err != nil {
		log.WithField("error", err.Error()).Debug("AWS Pod Identity: could not detect cluster name from IMDS")
		return ""
	}

	log.WithField("clusterName", name).Debug("AWS Pod Identity: cluster name from IMDS user-data")
	return name
}

// getClusterNameFromIMDS retrieves the EKS cluster name from EC2 instance metadata.
// EKS nodes run /etc/eks/bootstrap.sh <cluster-name> in user-data.
func getClusterNameFromIMDS(ctx context.Context) (string, error) {
	// Get IMDSv2 token
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPut, imdsTokenEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create IMDS token request: %w", err)
	}
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")

	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		return "", fmt.Errorf("IMDS token request failed: %w", err)
	}
	defer tokenResp.Body.Close()

	tokenBody, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read IMDS token: %w", err)
	}
	if tokenResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IMDS token request returned %d", tokenResp.StatusCode)
	}
	imdsToken := string(tokenBody)

	// Get user-data
	udReq, err := http.NewRequestWithContext(ctx, http.MethodGet, imdsUserDataEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create IMDS user-data request: %w", err)
	}
	udReq.Header.Set("X-aws-ec2-metadata-token", imdsToken)

	udResp, err := http.DefaultClient.Do(udReq)
	if err != nil {
		return "", fmt.Errorf("IMDS user-data request failed: %w", err)
	}
	defer udResp.Body.Close()

	if udResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IMDS user-data returned %d", udResp.StatusCode)
	}

	// Parse user-data line by line looking for /etc/eks/bootstrap.sh <cluster-name>
	scanner := bufio.NewScanner(udResp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.Index(line, "/etc/eks/bootstrap.sh"); idx != -1 {
			// Extract the first argument after the script path
			after := strings.TrimSpace(line[idx+len("/etc/eks/bootstrap.sh"):])
			fields := strings.Fields(after)
			if len(fields) > 0 {
				// Strip quotes if present
				name := strings.Trim(fields[0], "'\"")
				if name != "" {
					return name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("bootstrap.sh not found in user-data")
}

// getTokenViaPodIdentity exchanges a K8s token via the EKS AssumeRoleForPodIdentity API.
func (p *AWSProvider) getTokenViaPodIdentity(ctx context.Context, clusterName string, region string) (*repository.Token, error) {
	saName := p.k8s.sa.Name

	// Request K8s token with Pod Identity audience
	k8sToken, err := p.k8s.GetToken(ctx, PodIdentityAudience, "")
	if err != nil {
		return nil, fmt.Errorf("failed to request K8s token: %w", err)
	}

	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	log.WithFields(log.Fields{
		"serviceAccount": saName,
		"clusterName":    clusterName,
	}).Info("AWS Pod Identity: calling AssumeRoleForPodIdentity")

	client := eksauth.NewFromConfig(awsCfg)
	result, err := client.AssumeRoleForPodIdentity(ctx, &eksauth.AssumeRoleForPodIdentityInput{
		ClusterName: aws.String(clusterName),
		Token:       aws.String(k8sToken.Token),
	})
	if err != nil {
		return nil, fmt.Errorf("AssumeRoleForPodIdentity failed: %w", err)
	}

	log.WithFields(log.Fields{
		"serviceAccount": saName,
		"expiration":     result.Credentials.Expiration,
	}).Info("AWS Pod Identity: successfully obtained credentials")

	return &repository.Token{
		Type: repository.TokenTypeAWS,
		AWSCredentials: &repository.AWSCredentials{
			AccessKeyID:     *result.Credentials.AccessKeyId,
			SecretAccessKey: *result.Credentials.SecretAccessKey,
			SessionToken:    *result.Credentials.SessionToken,
			Expiration:      result.Credentials.Expiration,
			Region:          region,
		},
	}, nil
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
