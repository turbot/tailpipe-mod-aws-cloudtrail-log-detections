locals {
  mitre_v151_ta0008_t1021_004_common_tags = merge(local.mitre_v151_ta0008_common_tags, {
    mitre_technique_id = "T1021.004"
  })

  cloudtrail_logs_detect_ssh_activity_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0008_t1021_004" {
  title         = "T1021.004 Remote Services: SSH"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0008_t1021_004.md")
  children = [
    detection.cloudtrail_logs_detect_ssh_activity
  ]

  tags = local.mitre_v151_ta0008_t1021_004_common_tags
}

detection "cloudtrail_logs_detect_ssh_activity" {
  title       = "Detect Unauthorized SSH Activity"
  description = "Detect unauthorized use of SSH keys or attempts to establish SSH connections to EC2 instances."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_ssh_activity.md")
  query       = query.cloudtrail_logs_detect_ssh_activity

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0008:T1021.004"
  })
}

query "cloudtrail_logs_detect_ssh_activity" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ssh_activity_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'StartInstances'
      and user_identity.session_context.attributes.mfa_authenticated = 'false'
    order by
      event_time desc;
  EOQ
}
