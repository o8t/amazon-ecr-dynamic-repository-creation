import logging
import os
import sys
import boto3
import json
import re
import base64

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Semver regex pattern as specified
SEMVER_PATTERN = r'^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$'

def is_semver_tag(tag):
    """Check if a tag matches semver pattern"""
    return re.match(SEMVER_PATTERN, tag) is not None

def create_repository(event, context):
    """Handle repository creation for RepositoryNotFoundException events"""
    account_id = event["account"]
    repository = event["detail"]["requestParameters"]["repositoryName"]

    client = boto3.client("ecr")

    try:
        repositories = client.describe_repositories(
            registryId=account_id, repositoryNames=[repository]
        )["repositories"]
    except:
        logger.info("failed to lookup repository %s, probably missing - creating the repository now...", repository)
        repositories = []

    if not repositories:
        try: 
            scan_on_push = bool(os.environ["REPO_SCAN_ON_PUSH"])
            mutability   = os.environ["IMAGE_TAG_MUTABILITY"]

            tags = []
            if os.environ["REPO_TAGS"]:
                 tags = [{"Key": k, "Value": v} for (k, v) in json.loads(os.environ["REPO_TAGS"]).items()]
        except Exception as e:
            logger.error("env variable malformed: %s", e)
            
        try:
            client.create_repository(
                registryId=account_id,
                repositoryName=repository,
                imageTagMutability=mutability,
                imageScanningConfiguration={"scanOnPush": scan_on_push},
                encryptionConfiguration={"encryptionType": "KMS"},
                tags=tags,
            )
            logger.info("created %s repository", repository)
        except Exception as e:
            logger.error("failed to create repository %s: %s", repository, e)
            sys.exit(1)

def replicate_image(event, context):
    """Handle image replication for PutImage events with semver tags"""
    try:
        # Extract image details from the event
        detail = event["detail"]
        source_region = detail["awsRegion"]
        source_account = event["account"]
        
        response_elements = detail["responseElements"]
        image_info = response_elements["image"]
        image_id = image_info["imageId"]
        
        repository_name = detail["requestParameters"]["repositoryName"]
        image_tag = image_id.get("imageTag")
        image_digest = image_id.get("imageDigest")
        
        logger.info(f"Processing image push: repository={repository_name}, tag={image_tag}, digest={image_digest}")
        
        # Check if the tag is a semver tag
        if not image_tag or not is_semver_tag(image_tag):
            logger.info(f"Image tag '{image_tag}' is not a semver tag, skipping replication")
            return
        
        logger.info(f"Found semver tag '{image_tag}', proceeding with replication")
        
        # Get destination configuration from environment variables
        dest_account_id = os.environ["DEST_ECR_ACCOUNT_ID"]
        dest_region = os.environ["DEST_ECR_REGION"]
        dest_role_arn = os.environ.get("DEST_ECR_ROLE_ARN", "")
        
        # Set up source ECR client
        source_ecr = boto3.client("ecr", region_name=source_region)
        
        # Set up destination ECR client (with cross-account role if specified)
        if dest_role_arn:
            sts = boto3.client("sts")
            assumed_role = sts.assume_role(
                RoleArn=dest_role_arn,
                RoleSessionName=f"ecr-replication-{repository_name}-{image_tag}"
            )
            dest_credentials = assumed_role["Credentials"]
            dest_ecr = boto3.client(
                "ecr",
                region_name=dest_region,
                aws_access_key_id=dest_credentials["AccessKeyId"],
                aws_secret_access_key=dest_credentials["SecretAccessKey"],
                aws_session_token=dest_credentials["SessionToken"]
            )
        else:
            dest_ecr = boto3.client("ecr", region_name=dest_region)
        
        # Ensure destination repository exists
        try:
            dest_ecr.describe_repositories(
                registryId=dest_account_id,
                repositoryNames=[repository_name]
            )
            logger.info(f"Destination repository {repository_name} exists")
        except dest_ecr.exceptions.RepositoryNotFoundException:
            logger.info(f"Creating destination repository {repository_name}")
            dest_ecr.create_repository(
                registryId=dest_account_id,
                repositoryName=repository_name,
                imageTagMutability=os.environ["IMAGE_TAG_MUTABILITY"],
                imageScanningConfiguration={"scanOnPush": bool(os.environ["REPO_SCAN_ON_PUSH"])},
                encryptionConfiguration={"encryptionType": "KMS"}
            )
        
        # Check if image already exists in destination
        try:
            dest_images = dest_ecr.describe_images(
                registryId=dest_account_id,
                repositoryName=repository_name,
                imageIds=[{"imageTag": image_tag}]
            )
            if dest_images["imageDetails"]:
                logger.info(f"Image {repository_name}:{image_tag} already exists in destination, skipping")
                return
        except dest_ecr.exceptions.ImageNotFoundException:
            logger.info(f"Image {repository_name}:{image_tag} does not exist in destination, proceeding with replication")
        
        # Get the manifest from source
        source_manifest = source_ecr.get_download_url_for_layer(
            registryId=source_account,
            repositoryName=repository_name,
            layerDigest=image_digest
        ) if image_digest else None
        
        # Get image manifest and layers from source
        source_image = source_ecr.batch_get_image(
            registryId=source_account,
            repositoryName=repository_name,
            imageIds=[{"imageTag": image_tag}]
        )
        
        if not source_image["images"]:
            logger.error(f"Could not retrieve image {repository_name}:{image_tag} from source")
            return
        
        source_manifest_text = source_image["images"][0]["imageManifest"]
        source_manifest_media_type = source_image["images"][0].get("imageMediaType", "application/vnd.docker.distribution.manifest.v2+json")
        
        # Put the image in destination
        dest_ecr.put_image(
            registryId=dest_account_id,
            repositoryName=repository_name,
            imageManifest=source_manifest_text,
            imageMediaType=source_manifest_media_type,
            imageTag=image_tag
        )
        
        logger.info(f"Successfully replicated image {repository_name}:{image_tag} from {source_account}:{source_region} to {dest_account_id}:{dest_region}")
        
    except Exception as e:
        logger.error(f"Failed to replicate image: {e}")
        raise

def run(event, context):
    """Main handler function"""
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Determine event type based on eventName
        event_name = event["detail"]["eventName"]
        
        if event_name == "InitiateLayerUpload":
            # This is a repository creation event
            logger.info("Handling repository creation event")
            create_repository(event, context)
        elif event_name == "PutImage":
            # This is an image push event
            logger.info("Handling image push event")
            replicate_image(event, context)
        else:
            logger.warning(f"Unknown event type: {event_name}")
            
    except Exception as e:
        logger.error(f"Error processing event: {e}")
        raise
