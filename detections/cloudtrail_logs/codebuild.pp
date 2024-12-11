locals {
  cloudtrail_logs_detect_codebuild_project_visibility_updates_sql_columns        = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.projectArn")
}

benchmark "cloudtrail_logs_codebuild_detections" {
  title       = "CloudTrail Log CodeBuild Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's CodeBuild logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_codebuild_project_visibility_updates,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/CodeBuild"
  })
}

detection "cloudtrail_logs_detect_codebuild_project_visibility_updates" {
  title       = "Detect CodeBuild Projects Visibility Updates"
  description = "Detect CodeBuild projects visibility updates to check whether projects are publicly accessible."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_codebuild_project_visibility_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "cloudtrail_logs_detect_codebuild_project_visibility_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_codebuild_project_visibility_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'codebuild.amazonaws.com'
      and event_name = 'UpdateProjectVisibility'
      and (request_parameters.projectVisibility) = 'PUBLIC_READ'
      and error_code is null
    order by
      event_time desc;
  EOQ
}