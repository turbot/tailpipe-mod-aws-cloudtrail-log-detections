locals {
  mitre_v151_ta0008_t1078_common_tags = merge(local.mitre_v151_ta0008_common_tags, {
    mitre_technique_id = "T1078"
  })

  cloudtrail_logs_detect_valid_accounts_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0008_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0008_t1078.md")
  children = [
    detection.cloudtrail_logs_detect_valid_accounts
  ]

  tags = local.mitre_v151_ta0008_t1078_common_tags
}

detection "cloudtrail_logs_detect_valid_accounts" {
  title       = "Detect Use of Valid Accounts"
  description = "Detect use of compromised or unauthorized valid AWS accounts for lateral movement."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_valid_accounts.md")
  query       = query.cloudtrail_logs_detect_valid_accounts

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0008:T1078"
  })
}

query "cloudtrail_logs_detect_valid_accounts" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_valid_accounts_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'sts.amazonaws.com'
      and event_name = 'AssumeRole'
      and user_identity.session_context.attributes.mfa_authenticated = 'false'
    order by
      event_time desc;
  EOQ
}
