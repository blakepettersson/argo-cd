package v2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractAWSRegion(t *testing.T) {
	tests := []struct {
		name     string
		repoURL  string
		expected string
	}{
		{
			name:     "standard ECR URL",
			repoURL:  "123456789012.dkr.ecr.us-west-2.amazonaws.com/my-repo",
			expected: "us-west-2",
		},
		{
			name:     "ECR URL with oci:// prefix",
			repoURL:  "oci://123456789012.dkr.ecr.us-east-1.amazonaws.com/charts",
			expected: "us-east-1",
		},
		{
			name:     "ECR URL eu-central-1",
			repoURL:  "123456789012.dkr.ecr.eu-central-1.amazonaws.com/app",
			expected: "eu-central-1",
		},
		{
			name:     "ECR URL ap-southeast-1",
			repoURL:  "123456789012.dkr.ecr.ap-southeast-1.amazonaws.com/images",
			expected: "ap-southeast-1",
		},
		{
			name:     "ECR URL with path segments",
			repoURL:  "123456789012.dkr.ecr.us-west-2.amazonaws.com/team/project/app",
			expected: "us-west-2",
		},
		{
			name:     "GovCloud region",
			repoURL:  "123456789012.dkr.ecr.us-gov-west-1.amazonaws.com/secure-app",
			expected: "us-gov-west-1",
		},
		{
			name:     "China region",
			repoURL:  "123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn/app",
			expected: "cn-north-1",
		},
		{
			name:     "non-ECR URL defaults to us-east-1",
			repoURL:  "docker.io/library/nginx",
			expected: "us-east-1",
		},
		{
			name:     "invalid URL defaults to us-east-1",
			repoURL:  "not-a-valid-url",
			expected: "us-east-1",
		},
		{
			name:     "empty URL defaults to us-east-1",
			repoURL:  "",
			expected: "us-east-1",
		},
		{
			name:     "URL with only hostname",
			repoURL:  "123456789012.dkr.ecr.us-west-2.amazonaws.com",
			expected: "us-west-2",
		},
		{
			name:     "public ECR URL (different format)",
			repoURL:  "public.ecr.aws/amazonlinux/amazonlinux",
			expected: "us-east-1", // Public ECR has different format, should default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractAWSRegion(tt.repoURL)
			assert.Equal(t, tt.expected, result)
		})
	}
}