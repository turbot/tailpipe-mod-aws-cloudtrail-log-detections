locals {
  secretsmanager_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    folder  = "Secrets Manager"
    service = "AWS/SecretsManager"
  })
}

benchmark "secretsmanager_detections" {
  title       = "Secrets Manager Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for AWS Secrets Manager events."
  type        = "detection"
  children = [
    detection.secretsmanager_rotation_failures,
  ]

  tags = merge(local.secretsmanager_common_tags, {
    type = "Benchmark"
  })
}

detection "secretsmanager_rotation_failures" {
  title           = "AWS Secrets Manager Secret Rotation Failures"
  description     = "Detect when AWS Secrets Manager rotation fails for secrets. Failed rotations can lead to credential expiration, service disruptions, or continued use of potentially compromised credentials, increasing security risk."
  documentation   = file("./detections/docs/secretsmanager_rotation_failures.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.secretsmanager_rotation_failures

  tags = merge(local.secretsmanager_common_tags, {
    mitre_attack_ids = "TA0006:T1552"
    recommended      = "true"
  })
}

query "secretsmanager_rotation_failures" {
  sql = <<-EOQ
    select
      coalesce(json_extract_string(request_parameters, '$.secretId'), 'Unknown Secret') as resource,
      event_time,
      error_code,
      error_message,
      user_identity.arn as user_arn
    from
      aws_cloudtrail_log
    where
      event_source = 'secretsmanager.amazonaws.com'
      and (
        (event_name = 'RotateSecret' and error_code is not null)
        or (event_name = 'GetSecretValue' and error_code = 'AccessDeniedException')
        or (event_name = 'PutSecretValue' and error_code is not null)
      )
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ

  tags = local.secretsmanager_common_tags
}
