locals {
  mitre_v151_ta0010_t1537_common_tags = merge(local.mitre_v151_ta0010_common_tags, {
    mitre_technique_id = "T1537"
  })

  cloudtrail_logs_detect_cross_account_s3_copy_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0010_t1537" {
  title         = "T1537 Transfer Data to Cloud Account"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0010_t1537.md")
  children = [
    detection.cloudtrail_logs_detect_cross_account_s3_copy
  ]

  tags = local.mitre_v151_ta0010_t1537_common_tags
}

detection "cloudtrail_logs_detect_cross_account_s3_copy" {
  title       = "Detect Cross-Account S3 Data Copy"
  description = "Detect copying of S3 objects to other AWS accounts."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_cross_account_s3_copy.md")
  query       = query.cloudtrail_logs_detect_cross_account_s3_copy

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1537"
  })
}

query "cloudtrail_logs_detect_cross_account_s3_copy" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cross_account_s3_copy_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name in ('CopyObject')
      and request_parameters.destinationAccount is not null
    order by
      event_time desc;
  EOQ
}



