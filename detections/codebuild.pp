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
    detection.codebuild_project_environment_variable_updated,
    detection.codebuild_project_iam_role_updated,
    detection.codebuild_project_source_repository_updated,
    detection.codebuild_project_granted_public_access,
  ]

  tags = merge(local.codebuild_common_tags, {
    type = "Benchmark"
  })
}

detection "codebuild_project_granted_public_access" {
  title           = "CodeBuild Project Granted Public Access"
  description     = "Detect when a CodeBuild project was created with public access to check for risks of exposing build configurations, which could lead to unauthorized access and data breaches."
  documentation   = file("./detections/docs/codebuild_project_granted_public_access.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.codebuild_project_granted_public_access

  tags = merge(local.codebuild_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "codebuild_project_granted_public_access" {
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

detection "codebuild_project_iam_role_updated" {
  title           = "CodeBuild Project IAM Role Updated"
  description     = "Detect when an IAM role associated with CodeBuild project was updated to check for unauthorized changes that could grant excessive permissions, potentially leading to privilege escalation or unauthorized access."
  documentation   = file("./detections/docs/codebuild_project_iam_role_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.codebuild_project_iam_role_updated

  tags = merge(local.codebuild_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

query "codebuild_project_iam_role_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'codebuild.amazonaws.com'
      and event_name = 'UpdateProject'
      and (request_parameters ->> 'serviceRole') is not null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "codebuild_project_source_repository_updated" {
  title           = "CodeBuild Project Source Repository Updated"
  description     = "Detect when a source repository associated with CodeBuild projects was updated to check for unauthorized changes that could expose sensitive source code or credentials, potentially leading to data breaches or unauthorized access."
  documentation   = file("./detections/docs/codebuild_project_source_repository_updated.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.codebuild_project_source_repository_updated

  tags = merge(local.codebuild_common_tags, {
    mitre_attack_ids = "TA0001:T1566"
  })
}

query "codebuild_project_source_repository_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
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

detection "codebuild_project_environment_variable_updated" {
  title           = "CodeBuild Project Environment Variable Updated"
  description     = "Detect when a CodeBuild project's environment variable was updated to check for unauthorized changes that could expose sensitive information, potentially leading to data breaches or unauthorized access."
  documentation   = file("./detections/docs/codebuild_project_environment_variable_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.codebuild_project_environment_variable_updated

  tags = merge(local.codebuild_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "codebuild_project_environment_variable_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
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
