locals {
  mitre_v151_ta0008_t1550_001_common_tags = merge(local.mitre_v151_ta0008_common_tags, {
    mitre_technique_id = "T1550.001"
  })

  cloudtrail_logs_detect_application_access_token_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0008_t1550_001" {
  title         = "T1550.001 Application Access Token"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0008_t1550_001.md")
  children = [
    detection.cloudtrail_logs_detect_application_access_token
  ]

  tags = local.mitre_v151_ta0008_t1550_001_common_tags
}

detection "cloudtrail_logs_detect_application_access_token" {
  title       = "Detect Application Access Token Usage"
  description = "Detect unauthorized usage of application access tokens in AWS services."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_application_access_token.md")
  query       = query.cloudtrail_logs_detect_application_access_token

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0008:T1550.001"
  })
}

query "cloudtrail_logs_detect_application_access_token" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_application_access_token_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'CreateAccessKey'
      and error_code is null
    order by
      event_time desc;
  EOQ
}
