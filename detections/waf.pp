locals {
  waf_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/WAF"
  })

  waf_web_acl_logging_disabled_sql_columns                           = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.resourceArn')")
  waf_web_acl_disassociated_from_cloudfront_distribution_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.resourceArn')")
  waf_web_acl_disassociated_from_alb_sql_columns                     = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.resourceArn')")
  waf_rule_configured_for_unrestricted_ip_access_sql_columns         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.ruleArn')")
}

benchmark "waf_detections" {
  title       = "WAF Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for WAF events."
  type        = "detection"
  children = [
    detection.waf_rule_configured_for_unrestricted_ip_access,
    detection.waf_web_acl_disassociated_from_alb,
    detection.waf_web_acl_disassociated_from_cloudfront_distribution,
    detection.waf_web_acl_logging_disabled,
  ]

  tags = merge(local.waf_common_tags, {
    type = "Benchmark"
  })
}

detection "waf_web_acl_logging_disabled" {
  title           = "WAF Web ACL Logging Disabled"
  description     = "Detect when WAF Web ACLs have logging disabled to identify changes that could hinder monitoring and auditing, potentially obscuring malicious activity or misconfigurations."
  documentation   = file("./detections/docs/waf_web_acl_logging_disabled.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.waf_web_acl_logging_disabled

  tags = merge(local.waf_common_tags, {
    mitre_attack_ids = "TA0005:T1562.002"
  })
}

query "waf_web_acl_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.waf_web_acl_logging_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'wafv2.amazonaws.com'
      and event_name in ('DeleteLoggingConfiguration', 'PutLoggingConfiguration')
      and (request_parameters -> 'loggingConfiguration') is null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "waf_web_acl_disassociated_from_cloudfront_distribution" {
  title           = "WAF Web ACL Disassociated from CloudFront Distribution"
  description     = "Detect when a WAF Web ACL is disassociated from a CloudFront distribution, potentially exposing it to unauthorized access or attacks."
  documentation   = file("./detections/docs/waf_web_acl_disassociated_from_cloudfront_distribution.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.waf_web_acl_disassociated_from_cloudfront_distribution

  tags = merge(local.waf_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "waf_web_acl_disassociated_from_cloudfront_distribution" {
  sql = <<-EOQ
    select
      ${local.waf_web_acl_disassociated_from_cloudfront_distribution_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'wafv2.amazonaws.com'
      and event_name = 'DisassociateWebACL'
      and (request_parameters ->> 'resourceArn') like '%cloudfront::%:distribution/%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "waf_web_acl_disassociated_from_alb" {
  title           = "WAF Web ACL Disassociated from Application Load Balancer"
  description     = "Detect when a WAF Web ACL is disassociated from Application Load Balancers (ALBs), potentially exposing them to unauthorized access or attacks."
  documentation   = file("./detections/docs/waf_web_acl_disassociated_from_alb.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.waf_web_acl_disassociated_from_alb

  tags = merge(local.waf_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "waf_web_acl_disassociated_from_alb" {
  sql = <<-EOQ
    select
      ${local.waf_web_acl_disassociated_from_alb_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'wafv2.amazonaws.com'
      and event_name = 'DisassociateWebACL'
      and (request_parameters ->> 'resourceArn') like '%elasticloadbalancing:%:%:loadbalancer/app/%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "waf_rule_configured_for_unrestricted_ip_access" {
  title           = "WAF Rule Configured for Unrestricted IP Access"
  description     = "Detect when a WAF rule is configured to allow unrestricted IP access (e.g., 0.0.0.0/0), which could expose protected resources to unauthorized access or attacks."
  documentation   = file("./detections/docs/waf_rule_configured_for_unrestricted_ip_access.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.waf_rule_configured_for_unrestricted_ip_access

  tags = merge(local.waf_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "waf_rule_configured_for_unrestricted_ip_access" {
  sql = <<-EOQ
    select
      ${local.waf_rule_configured_for_unrestricted_ip_access_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'wafv2.amazonaws.com'
      and event_name in ('UpdateRule', 'PutRule')
      and (request_parameters ->> 'rules') like '%0.0.0.0/0%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
