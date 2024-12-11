locals {
  mitre_v151_ta0008_t1570_common_tags = merge(local.mitre_v151_ta0008_common_tags, {
    mitre_technique_id = "T1570"
  })

  cloudtrail_logs_detect_tool_transfer_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0008_t1570" {
  title         = "T1570 Lateral Tool Transfer"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0008_t1570.md")
  children = [
    detection.cloudtrail_logs_detect_tool_transfer
  ]

  tags = local.mitre_v151_ta0008_t1570_common_tags
}

detection "cloudtrail_logs_detect_tool_transfer" {
  title       = "Detect Lateral Tool Transfer"
  description = "Detect transfer of malicious tools or binaries between resources."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_tool_transfer.md")
  query       = query.cloudtrail_logs_detect_tool_transfer

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0008:T1570"
  })
}

query "cloudtrail_logs_detect_tool_transfer" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_tool_transfer_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name in ('PutObject', 'CopyObject')
      and request_parameters->>'key' like '%.exe%'
    order by
      event_time desc;
  EOQ
}
