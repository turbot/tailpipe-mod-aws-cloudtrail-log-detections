locals {
  route53_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/Route53"
  })

  detect_route53_domain_transfered_to_another_account_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.domainName')")
  detect_route53_associate_vpc_with_hosted_zone_sql_columns       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.hostedZoneId')")
}

benchmark "route53_detections" {
  title       = "Route 53 Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for Route 53 events."
  type        = "detection"
  children    = [
    detection.detect_route53_domain_transfers,
    detection.detect_route53_domains_with_transfer_lock_disabled,
    detection.detect_route53_vpc_associations_with_hosted_zones,
  ]

  tags = merge(local.route53_common_tags, {
    type    = "Benchmark"
  })
}

detection "detect_route53_domain_transfers" {
  title           = "Detect Route 53 Domain Transfers"
  description     = "Detect when Route 53 domains are transferred to another AWS account. Unauthorized domain transfers can result in the loss of control over your domains, leading to service disruption, domain hijacking, or malicious use of your web infrastructure."
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_route53_domain_transfers

  tags = merge(local.route53_common_tags, {
    mitre_attack_ids = "TA0040:T1531"
  })
}

detection "detect_route53_domains_with_transfer_lock_disabled" {
  title           = "Detect Route 53 Domains with Transfer Lock Disabled"
  description     = "Detect when the transfer lock on a Route 53 domain is disabled. Disabling the transfer lock can allow unauthorized domain transfers, leading to potential loss of control, domain hijacking, service disruptions, and malicious use of the domain."
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_route53_domains_with_transfer_lock_disabled

  tags = merge(local.route53_common_tags, {
    mitre_attack_ids = "TA0040:T1531"
  })
}

detection "detect_route53_vpc_associations_with_hosted_zones" {
  title          = "Detect Route 53 VPC Associations with Hosted Zones"
  description    = "Detect when a VPC is associated with a Route 53 hosted zone. Unauthorized VPC associations can expose DNS records to unintended networks, potentially enabling lateral movement, unauthorized access, or DNS-based attacks."
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_route53_vpc_associations_with_hosted_zones

  tags = merge(local.route53_common_tags, {
    mitre_attack_ids = "TA0003:T1078"
  })
}

query "detect_route53_domain_transfers" {
  sql = <<-EOQ
    select
      ${local.detect_route53_domain_transfered_to_another_account_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'route53.amazonaws.com'
      and event_name = 'TransferDomainToAnotherAwsAccount'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "detect_route53_domains_with_transfer_lock_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_route53_domain_transfered_to_another_account_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'route53.amazonaws.com'
      and event_name = 'DisableDomainTransferLock'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "detect_route53_vpc_associations_with_hosted_zones" {
  sql = <<-EOQ
    select
      ${local.detect_route53_associate_vpc_with_hosted_zone_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'route53.amazonaws.com'
      and event_name = 'AssociateVPCWithHostedZone'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
