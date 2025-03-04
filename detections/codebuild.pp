locals {
  codebuild_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    folder  = "CodeBuild"
    service = "AWS/CodeBuild"
  })

}

benchmark "codebuild_detections" {
  title       = "CodeBuild Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for CodeBuild events."
  type        = "detection"
  children = [
    detection.codebuild_project_build_failures,
    detection.codebuild_project_environment_variable_updated,
    detection.codebuild_project_service_role_updated,
    detection.codebuild_project_source_repository_updated,
    detection.codebuild_project_visibility_set_public,
  ]

  tags = merge(local.codebuild_common_tags, {
    type = "Benchmark"
  })
}

detection "codebuild_project_build_failures" {
  title           = "CodeBuild Project Build Failures"
  description     = "Detect when CodeBuild projects fail repeatedly. Multiple build failures may indicate configuration issues, security vulnerabilities in code, or potential supply chain attacks, disrupting CI/CD pipelines and delaying deployment of critical fixes."
  documentation   = file("./detections/docs/codebuild_project_build_failures.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.codebuild_project_build_failures

  tags = merge(local.codebuild_common_tags, {
    mitre_attack_ids = "TA0003:T1195"
  })
}

query "codebuild_project_build_failures" {
  sql = <<-EOQ
    with failed_builds as (
      select
        json_extract_string(request_parameters, '$.projectName') as project_name,
        event_time,
        user_identity.principal_id as principal_id
      from
        aws_cloudtrail_log
      where
        event_source = 'codebuild.amazonaws.com'
        and (
          (event_name = 'BatchGetBuilds' and json_extract_string(response_elements, '$.builds[*].buildStatus') like '%FAILED%')
          or (event_name = 'StopBuild')
          or (event_name = 'RetryBuild')
          or (event_name in ('StartBuild', 'CreateProject') and error_code is not null)
        )
        ${local.detection_sql_where_conditions}
    )
    select
      project_name as resource,
      count(*) as failure_count,
      min(event_time) as first_failure,
      max(event_time) as latest_failure,
      array_agg(distinct principal_id) as users
    from
      failed_builds
    where
      project_name is not null
    group by
      project_name
    having
      count(*) >= 3
    order by
      failure_count desc,
      latest_failure desc;
  EOQ

  tags = local.codebuild_common_tags
}

detection "codebuild_project_visibility_set_public" {
  title           = "CodeBuild Project Visibility Set Public"
  description     = "Detect when a CodeBuild project's visibility was set to public. Granting public access to a CodeBuild project can expose build configurations, credentials, or sensitive artifacts, increasing the risk of unauthorized access and data breaches."
  documentation   = file("./detections/docs/codebuild_project_visibility_set_public.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.codebuild_project_visibility_set_public

  tags = merge(local.codebuild_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "codebuild_project_visibility_set_public" {
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

  tags = local.codebuild_common_tags
}

detection "codebuild_project_service_role_updated" {
  title           = "CodeBuild Project Service Role Updated"
  description     = "Detect when an service role associated with CodeBuild project was updated to check for unauthorized changes that could grant excessive permissions, potentially leading to privilege escalation or unauthorized access."
  documentation   = file("./detections/docs/codebuild_project_service_role_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.codebuild_project_service_role_updated

  tags = merge(local.codebuild_common_tags, {
    mitre_attack_ids = "TA0004:T1098"
  })
}

query "codebuild_project_service_role_updated" {
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

  tags = local.codebuild_common_tags
}

detection "codebuild_project_source_repository_updated" {
  title           = "CodeBuild Project Source Repository Updated"
  description     = "Detect when a source repository associated with CodeBuild projects was updated to check for unauthorized changes that could expose sensitive source code or credentials, potentially leading to data breaches or unauthorized access."
  documentation   = file("./detections/docs/codebuild_project_source_repository_updated.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.codebuild_project_source_repository_updated

  tags = merge(local.codebuild_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
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

  tags = local.codebuild_common_tags
}

detection "codebuild_project_environment_variable_updated" {
  title           = "CodeBuild Project Environment Variable Updated"
  description     = "Detect when a CodeBuild project's environment variable was updated to check for unauthorized changes that could expose sensitive information, potentially leading to data breaches or unauthorized access."
  documentation   = file("./detections/docs/codebuild_project_environment_variable_updated.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.codebuild_project_environment_variable_updated

  tags = merge(local.codebuild_common_tags, {
    mitre_attack_ids = "TA0006:T1552.004"
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
      and (request_parameters -> 'environment' -> 'environmentVariables') is not null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ

  tags = local.codebuild_common_tags
}
