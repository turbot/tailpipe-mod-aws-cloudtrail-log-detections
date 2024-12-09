locals {
  mitre_v151_ta0010_t1567_common_tags = merge(local.mitre_v151_ta0010_common_tags, {
    mitre_technique_id = "T1567"
  })

  cloudtrail_logs_detect_s3_data_exfiltration_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0010_t1567" {
  title         = "T1567 Exfiltration Over Web Service"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0010_t1567.md")
  children = [
    detection.cloudtrail_logs_detect_s3_data_exfiltration
  ]

  tags = local.mitre_v151_ta0010_t1567_common_tags
}

detection "cloudtrail_logs_detect_s3_data_exfiltration" {
  title       = "Detect S3 Data Exfiltration"
  description = "Detect activities involving the downloading of data from S3 buckets."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_s3_data_exfiltration.md")
  query       = query.cloudtrail_logs_detect_s3_data_exfiltration

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "cloudtrail_logs_detect_s3_data_exfiltration" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_data_exfiltration_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name in ('GetObject', 'ListObjects')
    order by
      event_time desc;
  EOQ
}




