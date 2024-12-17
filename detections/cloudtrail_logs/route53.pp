locals {
  cloudtrail_log_detection_route53_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/Route53"
  })

  cloudtrail_logs_detect_route53_domain_transfered_to_another_account_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.domainName")
  cloudtrail_logs_detect_route53_associate_vpc_with_hosted_zone_sql_columns       = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.hostedZoneId")
}

benchmark "cloudtrail_logs_route53_detections" {
  title       = "Route 53"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for Route 53 events."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_route53_domain_transfered_to_another_accounts,
    detection.cloudtrail_logs_detect_transfer_lock_disabled_route53_domains,
    detection.cloudtrail_logs_detect_route53_vpc_associations_with_hosted_zones,
  ]

  tags = merge(local.cloudtrail_log_detection_route53_common_tags, {
    type    = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_route53_domain_transfered_to_another_accounts" {
  title       = "Detect Route 53 Domains Transfered to Another Account"
  description = "Detect Route 53 domains transfered to another account to check for unauthorized domain transfers."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_route53_domain_transfered_to_another_accounts

  tags = merge(local.cloudtrail_log_detection_route53_common_tags, {
    mitre_attack_ids = "TA0040:T1531"
  })
}

detection "cloudtrail_logs_detect_transfer_lock_disabled_route53_domains" {
  title       = "Detect Route 53 Domains Transfer Lock Disabled"
  description = "Detect Route 53 domains transfer lock disabled to check for unauthorized domain transfers."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_transfer_lock_disabled_route53_domains

  tags = merge(local.cloudtrail_log_detection_route53_common_tags, {
    mitre_attack_ids = "TA0040:T1531"
  })
}

detection "cloudtrail_logs_detect_route53_vpc_associations_with_hosted_zones" {
  title       = "Detect Route 53 VPC Associations with Hosted Zones"
  description = "Detect Route 53 VPC association with hosted zones to check for unauthorized VPC associations."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_route53_vpc_associations_with_hosted_zones

  tags = merge(local.cloudtrail_log_detection_route53_common_tags, {
    mitre_attack_ids = "TA0003:T1078"
  })
}

query "cloudtrail_logs_detect_route53_domain_transfered_to_another_accounts" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_route53_domain_transfered_to_another_account_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'route53.amazonaws.com'
      and event_name = 'TransferDomainToAnotherAwsAccount'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_transfer_lock_disabled_route53_domains" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_route53_domain_transfered_to_another_account_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'route53.amazonaws.com'
      and event_name = 'DisableDomainTransferLock'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_route53_vpc_associations_with_hosted_zones" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_route53_associate_vpc_with_hosted_zone_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'route53.amazonaws.com'
      and event_name = 'AssociateVPCWithHostedZone'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}
