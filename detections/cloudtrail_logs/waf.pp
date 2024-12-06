benchmark "cloudtrail_logs_waf_detections" {
  title       = "CloudTrail Log WAF Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's WAF logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_waf_web_acl_deletion_updates,
    detection.cloudtrail_logs_detect_waf_disassociation,
  ]
}

detection "cloudtrail_logs_detect_waf_web_acl_deletion_updates" {
  title       = "Detect WAF Web ACL Deletion Updates"
  description = "Detect WAF web ACL deletion updates to check for unauthorized changes."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_waf_web_acl_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_waf_disassociation" {
  title       = "Detect WAF Disassociation"
  description = "Detect when WAF is disassociated."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_waf_disassociation

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1498"
  })
}

query "cloudtrail_logs_detect_waf_web_acl_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_waf_web_acl_deletion_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'DeleteWebACL'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_waf_disassociation" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_waf_disassociation_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'DisassociateWebACL'
      and error_code is null
    order by
      event_time desc;
  EOQ
}