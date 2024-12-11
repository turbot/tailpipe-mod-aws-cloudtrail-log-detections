locals {
  mitre_v151_ta0040_t1562_001_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1562.001"
  })

  cloudtrail_logs_detect_impair_defenses_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0040_t1562_001" {
  title         = "T1562.001 Disable or Modify Tools"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1562_001.md")
  children = [
    detection.cloudtrail_logs_detect_impair_defenses
  ]

  tags = local.mitre_v151_ta0040_t1562_001_common_tags
}

detection "cloudtrail_logs_detect_impair_defenses" {
  title       = "Detect Defense Impairment"
  description = "Detect attempts to disable CloudTrail logging or modify security configurations."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_impair_defenses.md")
  query       = query.cloudtrail_logs_detect_impair_defenses

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1562.001"
  })
}

query "cloudtrail_logs_detect_impair_defenses" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_impair_defenses_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name in ('StopLogging', 'DeleteTrail', 'UpdateTrail')
      and error_code is null
    order by
      event_time desc;
  EOQ
}
