locals {
  mitre_v151_ta0007_t1083_common_tags = merge(local.mitre_v151_ta0007_common_tags, {
    mitre_technique_id = "T1083"
  })

  cloudtrail_logs_detect_s3_object_discovery_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0007_t1083" {
  title         = "T1083 File and Directory Discovery"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0007_t1083.md")
  children = [
    detection.cloudtrail_logs_detect_s3_object_discovery
  ]

  tags = local.mitre_v151_ta0007_t1083_common_tags
}

detection "cloudtrail_logs_detect_s3_object_discovery" {
  title       = "Detect S3 Object Discovery"
  description = "Detect listing or viewing objects within S3 buckets."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_s3_object_discovery.md")
  query       = query.cloudtrail_logs_detect_s3_object_discovery

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0007:T1083"
  })
}

query "cloudtrail_logs_detect_s3_object_discovery" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_object_discovery_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name in ('ListObjects', 'ListBuckets')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

