locals {
  mitre_v151_ta0008_t1021_002_common_tags = merge(local.mitre_v151_ta0008_common_tags, {
    mitre_technique_id = "T1021.002"
  })

  cloudtrail_logs_detect_smb_activity_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0008_t1021_002" {
  title         = "T1021.002 Remote Services: SMB/Windows Admin Shares"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0008_t1021_002.md")
  children = [
    detection.cloudtrail_logs_detect_smb_activity
  ]

  tags = local.mitre_v151_ta0008_t1021_002_common_tags
}

detection "cloudtrail_logs_detect_smb_activity" {
  title       = "Detect SMB/Windows Admin Share Activity"
  description = "Detect lateral movement via Windows Admin Shares (e.g., RDP)."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_smb_activity.md")
  query       = query.cloudtrail_logs_detect_smb_activity

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0008:T1021.002"
  })
}

query "cloudtrail_logs_detect_smb_activity" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_smb_activity_sql_columns}
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
