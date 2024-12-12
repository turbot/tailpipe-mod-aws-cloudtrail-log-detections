locals {
  cloudtrail_logs_detect_waf_web_acl_deletion_updates_sql_columns                 = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.id")
  cloudtrail_logs_detect_waf_disassociation_sql_columns                          = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.resourceArn")
}

benchmark "cloudtrail_logs_waf_detections" {
  title       = "CloudTrail Log WAF Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's WAF logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_waf_web_acl_deletion_updates,
    detection.cloudtrail_logs_detect_waf_disassociation,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/WAF"
  })
}

detection "cloudtrail_logs_detect_waf_web_acl_deletion_updates" {
  title       = "Detect WAF Web ACLs Deletion Updates"
  description = "Detect WAF web ACLs deletion updates to check for unauthorized changes."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_waf_web_acl_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_waf_disassociation" {
  title       = "Detect WAFs Disassociation"
  description = "Detect when WAFs are disassociated."
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
      ${local.cloudtrail_log_detections_where_conditions}
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
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}