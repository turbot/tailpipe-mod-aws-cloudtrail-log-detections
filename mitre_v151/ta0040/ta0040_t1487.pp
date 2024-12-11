locals {
  mitre_v151_ta0040_t1487_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1487"
  })

  cloudtrail_logs_detect_data_manipulation_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0040_t1487" {
  title         = "T1487 Data Manipulation"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1487.md")
  children = [
    detection.cloudtrail_logs_detect_data_manipulation
  ]

  tags = local.mitre_v151_ta0040_t1487_common_tags
}

detection "cloudtrail_logs_detect_data_manipulation" {
  title       = "Detect Data Manipulation"
  description = "Detect unauthorized modifications to data in S3 or RDS."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_data_manipulation.md")
  query       = query.cloudtrail_logs_detect_data_manipulation

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1487"
  })
}

query "cloudtrail_logs_detect_data_manipulation" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_data_manipulation_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source in ('s3.amazonaws.com', 'rds.amazonaws.com')
      and event_name in ('PutObject', 'ModifyDBInstance')
      and error_code is null
    order by
      event_time desc;
  EOQ
}
