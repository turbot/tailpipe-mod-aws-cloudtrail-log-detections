locals {
  mitre_v151_ta0040_t1490_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1490"
  })

  cloudtrail_logs_detect_inhibit_recovery_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0040_t1490" {
  title         = "T1490 Inhibit System Recovery"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1490.md")
  children = [
    detection.cloudtrail_logs_detect_inhibit_recovery
  ]

  tags = local.mitre_v151_ta0040_t1490_common_tags
}

detection "cloudtrail_logs_detect_inhibit_recovery" {
  title       = "Detect Inhibition of System Recovery"
  description = "Detect deletion of EBS snapshots or recovery points."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_inhibit_recovery.md")
  query       = query.cloudtrail_logs_detect_inhibit_recovery

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1490"
  })
}

query "cloudtrail_logs_detect_inhibit_recovery" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_inhibit_recovery_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('DeleteSnapshot', 'DeleteRecoveryPoint')
      and error_code is null
    order by
      event_time desc;
  EOQ
}
