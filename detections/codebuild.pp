locals {
  codebuild_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/CodeBuild"
  })

}

benchmark "codebuild_detections" {
  title       = "CodeBuild Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for CodeBuild events."
  type        = "detection"
  children = [
    detection.codebuild_projects_environment_variable_updated,
    detection.codebuild_projects_iam_role_updated,
    detection.codebuild_projects_source_repository_updated,
    detection.codebuild_projects_public_access_granted,
  ]

  tags = merge(local.codebuild_common_tags, {
    type = "Benchmark"
  })
}

detection "codebuild_projects_public_access_granted" {
  title           = "CodeBuild Projects Public Access Granted"
  description     = "Detect when CodeBuild projects were made publicly accessible to check for misconfigurations that could expose projects to unauthorized access or data leaks."
  # documentation   = file("./detections/docs/detect_public_access_granted_to_codebuild_projects.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.codebuild_projects_public_access_granted

  tags = merge(local.codebuild_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "codebuild_projects_public_access_granted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_codebuild_project_arn}
    from
      aws_cloudtrail_log
    where
      event_source = 'codebuild.amazonaws.com'
      and event_name = 'UpdateProjectVisibility'
      and (request_parameters ->> 'projectVisibility') = 'PUBLIC_READ'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "codebuild_projects_iam_role_updated" {
  title           = "CodeBuild Projects IAM Role Updated"
  description     = "Detect when IAM roles associated with CodeBuild projects were updated to check for potential privilege escalations or unauthorized access."
  # documentation   = file("./detections/docs/detect_codebuild_projects_with_iam_role_updates.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.codebuild_projects_iam_role_updated

  tags = merge(local.codebuild_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

query "codebuild_projects_iam_role_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_codebuild_project_arn}
    from
      aws_cloudtrail_log
    where
      event_source = 'codebuild.amazonaws.com'
      and event_name = 'UpdateProject'
      and (request_parameters ->> 'roleArn') is not null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "codebuild_projects_source_repository_updated" {
  title           = "CodeBuild Projects Source Repository Updated"
  description     = "Detect when source repositories associated with CodeBuild projects were updated to check for changes that could redirect builds to unauthorized or malicious repositories, compromising code integrity and security."
  # documentation   = file("./detections/docs/detect_codebuild_projects_with_source_repository_updates.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.codebuild_projects_source_repository_updated

  tags = merge(local.codebuild_common_tags, {
    mitre_attack_ids = "TA0001:T1566"
  })
}

query "codebuild_projects_source_repository_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_codebuild_project_arn}
    from
      aws_cloudtrail_log
    where
      event_source = 'codebuild.amazonaws.com'
      and event_name = 'UpdateProject'
      and (request_parameters -> 'source' ->> 'location') is not null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "codebuild_projects_environment_variable_updated" {
  title           = "CodeBuild Projects Environment Variable Updated"
  description     = "Detect when environment variables associated with CodeBuild projects were updated to check for unauthorized changes to sensitive values such as access tokens or API keys, potentially leading to privilege escalation or data exfiltration."
  # documentation   = file("./detections/docs/detect_codebuild_projects_with_environment_variable_updates.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.codebuild_projects_environment_variable_updated

  tags = merge(local.codebuild_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "codebuild_projects_environment_variable_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_codebuild_project_arn}
    from
      aws_cloudtrail_log
    where
      event_source = 'codebuild.amazonaws.com'
      and event_name = 'UpdateProject'
      and (request_parameters -> 'environment' ->> 'environmentVariables') is not null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
