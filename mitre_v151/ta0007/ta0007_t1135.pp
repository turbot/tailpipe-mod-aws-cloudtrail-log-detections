locals {
  mitre_v151_ta0007_t1135_common_tags = merge(local.mitre_v151_ta0007_common_tags, {
    mitre_technique_id = "T1135"
  })

  cloudtrail_logs_detect_efs_share_discovery_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0007_t1135" {
  title         = "T1135 Network Share Discovery"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0007_t1135.md")
  children = [
    detection.cloudtrail_logs_detect_efs_share_discovery
  ]

  tags = local.mitre_v151_ta0007_t1135_common_tags
}

detection "cloudtrail_logs_detect_efs_share_discovery" {
  title       = "Detect EFS Network Share Discovery"
  description = "Detect querying for EFS file system shares."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_efs_share_discovery.md")
  query       = query.cloudtrail_logs_detect_efs_share_discovery

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0007:T1135"
  })
}

query "cloudtrail_logs_detect_efs_share_discovery" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_efs_share_discovery_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'elasticfilesystem.amazonaws.com'
      and event_name in ('DescribeFileSystems')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

