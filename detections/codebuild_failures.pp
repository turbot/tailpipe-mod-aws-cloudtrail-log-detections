locals {
  codebuild_failures_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    folder  = "CodeBuild"
    service = "AWS/CodeBuild"
  })
}

detection "codebuild_project_build_failures" {
  title           = "CodeBuild Project Build Failures"
  description     = "Detect when CodeBuild projects fail repeatedly. Multiple build failures may indicate configuration issues, security vulnerabilities in code, or potential supply chain attacks, disrupting CI/CD pipelines and delaying deployment of critical fixes."
  documentation   = file("./detections/docs/codebuild_project_build_failures.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.codebuild_project_build_failures

  tags = merge(local.codebuild_failures_common_tags, {
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

  tags = local.codebuild_failures_common_tags
}
