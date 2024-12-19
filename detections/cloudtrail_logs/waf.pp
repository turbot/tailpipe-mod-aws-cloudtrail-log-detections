locals {
  cloudtrail_log_detection_waf_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/WAF"
  })

  cloudtrail_logs_detect_waf_web_acl_deletions_sql_columns       = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.id')")
  cloudtrail_logs_detect_waf_web_acl_disassociations_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.resourceArn')")
}

benchmark "cloudtrail_logs_waf_detections" {
  title       = "WAF Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for WAF events."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_waf_web_acl_deletions,
    detection.cloudtrail_logs_detect_waf_web_acl_disassociations,
  ]

  tags = merge(local.cloudtrail_log_detection_waf_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_waf_web_acl_deletions" {
  title           = "Detect WAF Web ACL Deletions"
  description     = "Detect when a WAF web ACL is deleted to check for potential disruptions to web application protections, which could expose applications to malicious traffic or DDoS attacks."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_waf_web_acl_deletions

  tags = merge(local.cloudtrail_log_detection_waf_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

detection "cloudtrail_logs_detect_waf_web_acl_disassociations" {
  title           = "Detect WAF Web ACL Disassociations"
  description     = "Detect when a WAF web ACL is disassociated from a resource to check for intentional bypassing of security protections or misconfigurations that could allow unrestricted access to web applications."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_waf_web_acl_disassociations

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1498"
  })
}

query "cloudtrail_logs_detect_waf_web_acl_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_waf_web_acl_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source in ('waf.amazonaws.com', 'wafv2.amazonaws.com')
      and event_name = 'DeleteWebACL'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_waf_web_acl_disassociations" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_waf_web_acl_disassociations_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'wafv2.amazonaws.com'
      and event_name = 'DisassociateWebACL'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}
