locals {
  cloudtrail_log_detection_codebuild_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/CodeBuild"
  })

  cloudtrail_logs_detect_public_access_granted_to_codebuild_projects_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.projectArn')")
}

benchmark "cloudtrail_logs_codebuild_detections" {
  title       = "CodeBuild Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for CodeBuild events."
  type        = "detection"
  children = [
    detection.cloudtrail_logs_detect_codebuild_projects_with_environment_variable_changes,
    detection.cloudtrail_logs_detect_codebuild_projects_with_iam_role_changes,
    detection.cloudtrail_logs_detect_codebuild_projects_with_source_repository_changes,
    detection.cloudtrail_logs_detect_public_access_granted_to_codebuild_projects,
  ]

  tags = merge(local.cloudtrail_log_detection_codebuild_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_public_access_granted_to_codebuild_projects" {
  title           = "Detect Public Access Granted to CodeBuild Projects"
  description     = "Detect CodeBuild project visibility updates to check for misconfigurations that could expose projects publicly, leading to unauthorized access or data leaks."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_public_access_granted_to_codebuild_projects

  tags = merge(local.cloudtrail_log_detection_codebuild_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "cloudtrail_logs_detect_public_access_granted_to_codebuild_projects" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_public_access_granted_to_codebuild_projects_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'codebuild.amazonaws.com'
      and event_name = 'UpdateProjectVisibility'
      and json_extract_string(request_parameters, '$.projectVisibility') = 'PUBLIC_READ'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_codebuild_projects_with_iam_role_changes" {
  title           = "Detect CodeBuild Projects with IAM Role Changes"
  description     = "Detect updates to the IAM role associated with CodeBuild projects to check for potential privilege escalations or unauthorized access."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_codebuild_projects_with_iam_role_changes

  tags = merge(local.cloudtrail_log_detection_codebuild_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

query "cloudtrail_logs_detect_codebuild_projects_with_iam_role_changes" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_public_access_granted_to_codebuild_projects_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'codebuild.amazonaws.com'
      and event_name = 'UpdateProject'
      and json_extract_string(request_parameters, '$.roleArn') is not null
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_codebuild_projects_with_source_repository_changes" {
  title           = "Detect CodeBuild Projects with Source Repository Changes"
  description     = "Detect updates to CodeBuild source repositories to check for changes that could redirect builds to unauthorized or malicious repositories, compromising code integrity and security."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_codebuild_projects_with_source_repository_changes

  tags = merge(local.cloudtrail_log_detection_codebuild_common_tags, {
    mitre_attack_ids = "TA0001:T1566"
  })
}

query "cloudtrail_logs_detect_codebuild_projects_with_source_repository_changes" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_public_access_granted_to_codebuild_projects_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'codebuild.amazonaws.com'
      and event_name = 'UpdateProject'
      and json_extract_string(request_parameters, '$.source.location') is not null
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_codebuild_projects_with_environment_variable_changes" {
  title           = "Detect CodeBuild Projects with Environment Variable Changes"
  description     = "Detect updates to CodeBuild environment variables to check for unauthorized changes to sensitive values like access tokens or API keys, which could lead to privilege escalation or data exfiltration."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_codebuild_projects_with_environment_variable_changes

  tags = merge(local.cloudtrail_log_detection_codebuild_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_logs_detect_codebuild_projects_with_environment_variable_changes" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_public_access_granted_to_codebuild_projects_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'codebuild.amazonaws.com'
      and event_name = 'UpdateProject'
      and json_extract_string(request_parameters, '$.environment.environmentVariables') is not null
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}
