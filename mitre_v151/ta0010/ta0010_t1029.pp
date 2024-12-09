locals {
  mitre_v151_ta0010_t1029_common_tags = merge(local.mitre_v151_ta0010_common_tags, {
    mitre_technique_id = "T1029"
  })

  cloudtrail_logs_detect_data_compression_for_exfiltration_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0010_t1029" {
  title         = "T1029 Data Compressed Before Exfiltration"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0010_t1029.md")
  children = [
    detection.cloudtrail_logs_detect_data_compression_for_exfiltration
  ]

  tags = local.mitre_v151_ta0010_t1029_common_tags
}

detection "cloudtrail_logs_detect_data_compression_for_exfiltration" {
  title       = "Detect Data Compression Before Exfiltration"
  description = "Detect data compression operations in preparation for exfiltration."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_data_compression_for_exfiltration.md")
  query       = query.cloudtrail_logs_detect_data_compression_for_exfiltration

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1029"
  })
}

query "cloudtrail_logs_detect_data_compression_for_exfiltration" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_data_compression_for_exfiltration_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name in ('PutObject', 'UploadPart')
      and request_parameters.compressionFormat is not null
    order by
      event_time desc;
  EOQ
}
