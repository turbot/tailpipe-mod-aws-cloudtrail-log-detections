locals {
  ssm_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/SSM"
  })
}

benchmark "ssm_detections" {
  title       = "SSM Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for SSM events."
  type        = "detection"
  children = [
    detection.ssm_document_shared_publicly,
  ]

  tags = merge(local.ssm_common_tags, {
    type = "Benchmark"
  })
}

detection "ssm_document_shared_publicly" {
  title           = "SSM Document Shared Publicly"
  description     = "Detect when an AWS Systems Manager document was shared publicly to check for potential risks of exposing sensitive configurations, scripts, or automation workflows to unauthorized access."
  documentation   = file("./detections/docs/ssm_document_shared_publicly.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.ssm_document_shared_publicly

  tags = merge(local.ssm_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "ssm_document_shared_publicly" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'ssm.amazonaws.com'
      and event_name = 'ModifyDocumentPermission'
      and json_contains(
        (request_parameters -> 'accountIdsToAdd'),
        '"all"'
      )
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
