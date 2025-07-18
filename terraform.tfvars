REPO_SCAN_ON_PUSH    = true
REPO_TAGS            = { "Team" = "platform", "Project" = "ecr-auto-repo" }
IMAGE_TAG_MUTABILITY = "IMMUTABLE"
SCAN_FREQUENCY       = "SCAN_ON_PUSH"
SCAN_TYPE           = "BASIC"

# Semver Image Replication Configuration
# Replace with your destination account ID and region
DEST_ECR_ACCOUNT_ID = "123456789012"  # Target AWS account ID for semver image replication
DEST_ECR_REGION     = "us-west-2"     # Target AWS region for semver image replication

# Optional: Cross-account role ARN for secure access
# DEST_ECR_ROLE_ARN = "arn:aws:iam::123456789012:role/ECRReplicationRole"