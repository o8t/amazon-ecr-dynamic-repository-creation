# Dynamic Repo Creation Integration 

resource "aws_lambda_function" "this" {
  filename         = data.archive_file.this.output_path
  function_name    = local.full_name
  description      = "create ecr repository."
  role             = aws_iam_role.this.arn
  handler          = "handler.run"
  runtime          = "python3.9"
  source_code_hash = data.archive_file.this.output_base64sha256
  timeout          = 120

  environment {
    variables = {
      IMAGE_TAG_MUTABILITY = var.IMAGE_TAG_MUTABILITY
      REPO_TAGS            = jsonencode(local.repo_tags)
      REPO_SCAN_ON_PUSH    = tostring(var.REPO_SCAN_ON_PUSH)
      DEST_ECR_ACCOUNT_ID  = var.DEST_ECR_ACCOUNT_ID
      DEST_ECR_REGION      = var.DEST_ECR_REGION
      DEST_ECR_ROLE_ARN    = var.DEST_ECR_ROLE_ARN
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = merge({ Name = local.full_name }, local.common_tags)
}

resource "aws_lambda_permission" "this" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.this.arn
  statement_id  = "AllowExecutionFromCloudWatch"
}

resource "aws_lambda_permission" "image_push" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.image_push.arn
  statement_id  = "AllowExecutionFromCloudWatchImagePush"
}

resource "aws_lambda_function_event_invoke_config" "this" {
  function_name                = aws_lambda_function.this.function_name
  maximum_event_age_in_seconds = 60
  maximum_retry_attempts       = 0
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${aws_lambda_function.this.function_name}"
  retention_in_days = 365
  tags              = merge({ Name = local.full_name }, local.common_tags)
}

resource "aws_cloudwatch_event_rule" "this" {

  name          = "cw-event-rule-for-non-existent-repo-${local.current_region}"
  description   = "monitor event for RepositoryNotFoundException error"
  event_pattern = <<-EOF
  {
    "source": ["aws.ecr"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "awsRegion": ["${local.current_region}"],
      "eventSource": ["ecr.amazonaws.com"],
      "eventName": ["InitiateLayerUpload"],
      "errorCode": ["RepositoryNotFoundException"]
    }
  }
  EOF

  tags = merge({ Name = local.full_name }, local.common_tags)
}

resource "aws_cloudwatch_event_rule" "image_push" {
  name          = "cw-event-rule-for-image-push-${local.current_region}"
  description   = "monitor event for ECR image push events to detect semver tags"
  event_pattern = <<-EOF
  {
    "source": ["aws.ecr"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "awsRegion": ["${local.current_region}"],
      "eventSource": ["ecr.amazonaws.com"],
      "eventName": ["PutImage"],
      "responseElements": {
        "image": {
          "imageId": {
            "imageTag": [{"exists": true}]
          }
        }
      }
    }
  }
  EOF

  tags = merge({ Name = "${local.full_name}-image-push" }, local.common_tags)
}

resource "aws_cloudwatch_event_target" "this" {
  target_id = aws_lambda_function.this.function_name
  rule      = aws_cloudwatch_event_rule.this.name
  arn       = aws_lambda_function.this.arn

  retry_policy {
    maximum_event_age_in_seconds = 1800
    maximum_retry_attempts       = 1
  }
}

resource "aws_cloudwatch_event_target" "image_push" {
  target_id = "${aws_lambda_function.this.function_name}-image-push"
  rule      = aws_cloudwatch_event_rule.image_push.name
  arn       = aws_lambda_function.this.arn

  retry_policy {
    maximum_event_age_in_seconds = 1800
    maximum_retry_attempts       = 1
  }
}