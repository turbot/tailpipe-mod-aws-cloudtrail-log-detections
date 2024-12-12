locals {
  mitre_v151_ta0010_t1530_common_tags = merge(local.mitre_v151_ta0010_common_tags, {
    mitre_technique_id = "T1530"
  })

  cloudtrail_logs_detect_s3_large_file_downloads_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0010_t1530" {
  title         = "T1530 Data Transfer Size Limits"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0010_t1530.md")
  children = [
    detection.cloudtrail_logs_detect_s3_large_file_downloads
  ]

  tags = local.mitre_v151_ta0010_t1530_common_tags
}

detection "cloudtrail_logs_detect_s3_large_file_downloads" {
  title       = "Detect Large Data Transfers"
  description = "Detect unusually large data transfers indicative of exfiltration."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_s3_large_file_downloads.md")
  query       = query.cloudtrail_logs_detect_s3_large_file_downloads

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1530"
  })
}

query "cloudtrail_logs_detect_s3_large_file_downloads" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_large_file_downloads_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name = 'GetObject'
      and cast(request_parameters->>'size' as integer) > 104857600 -- Size greater than 100MB
      and error_code is null
    order by
      event_time desc;
  EOQ
}
