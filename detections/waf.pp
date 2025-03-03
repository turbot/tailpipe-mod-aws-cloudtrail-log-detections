locals {
  waf_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    folder  = "WAF"
    service = "AWS/WAF"
  })
}

benchmark "waf_detections" {
  title       = "WAF Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for WAF events."
  type        = "detection"
  children = [
    detection.waf_web_acl_disassociated_from_cloudfront_distribution,
    detection.waf_web_acl_disassociated_from_elb_application_load_balancer,
    detection.waf_web_acl_logging_disabled,
  ]

  tags = merge(local.waf_common_tags, {
    type = "Benchmark"
  })
}

detection "waf_web_acl_logging_disabled" {
  title           = "WAF Web ACL Logging Disabled"
  description     = "Detect when logging was disabled for a WAF Web ACL to identify changes that could hinder monitoring and auditing, potentially obscuring malicious activity or misconfigurations."
  documentation   = file("./detections/docs/waf_web_acl_logging_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.waf_web_acl_logging_disabled

  tags = merge(local.waf_common_tags, {
    mitre_attack_ids = "TA0005:T1562.002"
  })
}

query "waf_web_acl_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_resource_arn}
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

  tags = local.waf_common_tags
}

detection "waf_web_acl_disassociated_from_cloudfront_distribution" {
  title           = "WAF Web ACL Disassociated from CloudFront Distribution"
  description     = "Detect when a WAF Web ACL was disassociated from a CloudFront distribution, potentially exposing it to unauthorized access or attacks."
  documentation   = file("./detections/docs/waf_web_acl_disassociated_from_cloudfront_distribution.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.waf_web_acl_disassociated_from_cloudfront_distribution

  tags = merge(local.waf_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "waf_web_acl_disassociated_from_cloudfront_distribution" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_resource_arn}
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

  tags = local.waf_common_tags
}

detection "waf_web_acl_disassociated_from_elb_application_load_balancer" {
  title           = "WAF Web ACL Disassociated from ELB Application Load Balancer"
  description     = "Detect when a WAF Web ACL was disassociated from an Application Load Balancer (ALB), potentially exposing it to unauthorized access or attacks."
  documentation   = file("./detections/docs/waf_web_acl_disassociated_from_elb_application_load_balancer.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.waf_web_acl_disassociated_from_elb_application_load_balancer

  tags = merge(local.waf_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "waf_web_acl_disassociated_from_elb_application_load_balancer" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_resource_arn}
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

  tags = local.waf_common_tags
}
