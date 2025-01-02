locals {
  cloudtrail_log_detection_waf_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/WAF"
  })

  cloudtrail_logs_detect_waf_acls_with_logging_disabled_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.resourceArn')")
  cloudtrail_logs_detect_waf_acl_disassociation_from_cloudfront_distributions_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.resourceArn')")
  cloudtrail_logs_detect_waf_acl_disassociation_from_alb_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.resourceArn')")
  cloudtrail_logs_detect_public_access_granted_to_waf_rules_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.ruleArn')")
}

benchmark "cloudtrail_logs_waf_detections" {
  title       = "WAF Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for WAF events."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_waf_acl_disassociation_from_alb,
    detection.cloudtrail_logs_detect_waf_acl_disassociation_from_cloudfront_distributions,
    detection.cloudtrail_logs_detect_waf_acls_with_logging_disabled,
    detection.cloudtrail_logs_detect_public_access_granted_to_waf_rules,
  ]

  tags = merge(local.cloudtrail_log_detection_waf_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_waf_acls_with_logging_disabled" {
  title           = "Detect WAF Web ACLs with Logging Disabled"
  description     = "Detect WAF Web ACLs with logging disabled to check for changes that could hinder monitoring and auditing, potentially obscuring malicious activity or misconfigurations."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_waf_acls_with_logging_disabled

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562.002"
  })
}

query "cloudtrail_logs_detect_waf_acls_with_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_waf_acls_with_logging_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'wafv2.amazonaws.com'
      and event_name in ('DeleteLoggingConfiguration', 'PutLoggingConfiguration')
      and json_extract_string(request_parameters, '$.loggingConfiguration') is null
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_waf_acl_disassociation_from_cloudfront_distributions" {
  title           = "Detect WAF Web ACL Disassociation from CloudFront Distributions"
  description     = "Detect when a WAF Web ACL is disassociated from CloudFront distributions, potentially exposing them to unauthorized access or attacks."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_waf_acl_disassociation_from_cloudfront_distributions

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_logs_detect_waf_acl_disassociation_from_cloudfront_distributions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_waf_acl_disassociation_from_cloudfront_distributions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'wafv2.amazonaws.com'
      and event_name = 'DisassociateWebACL'
      and json_extract_string(request_parameters, '$.resourceArn') like '%cloudfront::%:distribution/%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_waf_acl_disassociation_from_alb" {
  title           = "Detect WAF Web ACL Disassociation from Application Load Balancers"
  description     = "Detect when a WAF Web ACL is disassociated from Application Load Balancers (ALBs), potentially exposing them to unauthorized access or attacks."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_waf_acl_disassociation_from_alb

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_logs_detect_waf_acl_disassociation_from_alb" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_waf_acl_disassociation_from_alb_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'wafv2.amazonaws.com'
      and event_name = 'DisassociateWebACL'
      and json_extract_string(request_parameters, '$.resourceArn') like '%elasticloadbalancing:%:%:loadbalancer/app/%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_public_access_granted_to_waf_rules" {
  title           = "Detect Public Access Granted to WAF Rules"
  description     = "Detect when a WAF rule is configured to allow unrestricted public access (0.0.0.0/0), potentially exposing protected resources to unauthorized access or attacks."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_public_access_granted_to_waf_rules

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "cloudtrail_logs_detect_public_access_granted_to_waf_rules" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_public_access_granted_to_waf_rules_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'wafv2.amazonaws.com'
      and event_name in ('UpdateRule', 'PutRule')
      and json_extract_string(request_parameters, '$.rules') like '%0.0.0.0/0%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}
