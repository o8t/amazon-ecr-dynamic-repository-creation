# ECR Semver Image Replication

This document describes the enhanced ECR Lambda functionality that automatically replicates Docker images with semantic version (semver) tags to a destination ECR registry in another AWS account and region.

## Overview

The lambda function now handles two types of events:

1. **Repository Creation**: Creates ECR repositories when they don't exist (existing functionality)
2. **Semver Image Replication**: Automatically replicates images with semver tags to a destination ECR registry

## Semver Pattern

The lambda uses the following regex pattern to detect semver tags:

```regex
^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$
```

This pattern matches valid semantic versions like:
- `1.0.0`
- `2.1.3`
- `1.0.0-alpha`
- `1.0.0-alpha.1`
- `1.0.0+build.1`
- `1.0.0-alpha.1+build.1`

## Configuration

### Required Terraform Variables

Add these variables to your `terraform.tfvars` file:

```hcl
# Destination ECR configuration
DEST_ECR_ACCOUNT_ID = "123456789012"  # Target AWS account ID
DEST_ECR_REGION     = "us-west-2"     # Target AWS region

# Optional: Cross-account role ARN for assumed role access
DEST_ECR_ROLE_ARN   = "arn:aws:iam::123456789012:role/ECRReplicationRole"
```

### Cross-Account IAM Role (Recommended)

For secure cross-account access, create an IAM role in the destination account with the following trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::SOURCE_ACCOUNT_ID:role/dynamic-create-ecr-repo-lambda-role-REGION"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

And the following permissions policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:CreateRepository",
        "ecr:DescribeRepositories",
        "ecr:DescribeImages",
        "ecr:PutImage",
        "ecr:PutImageScanningConfiguration",
        "ecr:PutImageTagMutability"
      ],
      "Resource": "*"
    }
  ]
}
```

## How It Works

### Repository Creation Flow (Existing)

1. Developer attempts to push to non-existent ECR repository
2. CloudWatch captures `RepositoryNotFoundException` error
3. Lambda creates the repository with configured settings

### Semver Image Replication Flow (New)

1. Developer pushes image with semver tag (e.g., `1.2.3`) to source ECR
2. CloudWatch captures `PutImage` event
3. Lambda checks if the image tag matches semver pattern
4. If semver tag detected:
   - Assumes cross-account role (if configured)
   - Creates destination repository if it doesn't exist
   - Checks if image already exists in destination
   - Replicates image manifest and tag to destination ECR
   - Logs successful replication

### Event Flow Diagram

```
Source ECR (dev.ecr)          CloudWatch Events          Lambda Function
       │                            │                           │
       │ docker push image:1.2.3     │                           │
       ├─────────────────────────────▶│ PutImage event            │
       │                            ├──────────────────────────▶│
       │                            │                           │ Check semver pattern
       │                            │                           │ ✓ "1.2.3" matches
       │                            │                           │
       │                            │                           │ Assume cross-account role
       │                            │                           ├─────────────────────┐
       │                            │                           │                     ▼
       │                            │                           │            Destination ECR
       │                            │                           │            (shared.ecr)
       │                            │                           │                     │
       │                            │                           │ Replicate image     │
       │                            │                           ├────────────────────▶│
```

## Deployment

1. Update your `terraform.tfvars` with the required variables
2. Run `terraform plan` to review changes
3. Run `terraform apply` to deploy the updated infrastructure

## Monitoring

The lambda function logs all operations to CloudWatch Logs. Key log messages include:

- `Processing image push: repository=..., tag=..., digest=...`
- `Found semver tag '...', proceeding with replication`
- `Image tag '...' is not a semver tag, skipping replication`
- `Successfully replicated image ... from ... to ...`

## Security Considerations

1. **Cross-Account Access**: Use IAM roles with minimal required permissions
2. **Network Security**: Consider VPC endpoints for ECR access if using private subnets
3. **Encryption**: All replicated images maintain KMS encryption in destination
4. **Audit Trail**: All operations are logged via CloudTrail and CloudWatch

## Troubleshooting

### Common Issues

1. **Permission Denied**: Verify cross-account IAM role has correct permissions
2. **Image Not Found**: Check if source image exists and tag is correct
3. **Role Assumption Failed**: Verify trust relationship in destination account
4. **Repository Creation Failed**: Check ECR service limits and permissions

### Debug Steps

1. Check CloudWatch Logs for detailed error messages
2. Verify terraform variables are correctly set
3. Test cross-account role assumption manually with AWS CLI
4. Confirm ECR repositories exist in both source and destination accounts

## Example Terraform Configuration

```hcl
# terraform.tfvars
REPO_SCAN_ON_PUSH    = true
REPO_TAGS            = { "Environment" = "production", "Project" = "my-app" }
IMAGE_TAG_MUTABILITY = "IMMUTABLE"
SCAN_FREQUENCY       = "SCAN_ON_PUSH"
SCAN_TYPE           = "BASIC"

# Semver replication configuration
DEST_ECR_ACCOUNT_ID = "123456789012"
DEST_ECR_REGION     = "us-west-2"
DEST_ECR_ROLE_ARN   = "arn:aws:iam::123456789012:role/ECRReplicationRole"
```

This configuration will:
- Create repositories with scanning enabled and immutable tags
- Replicate any images with semver tags to account `123456789012` in `us-west-2`
- Use the specified IAM role for cross-account access