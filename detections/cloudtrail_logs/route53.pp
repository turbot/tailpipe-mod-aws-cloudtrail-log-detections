locals {
  cloudtrail_logs_detect_route53_domain_transfered_to_another_account_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.domainName")
  cloudtrail_logs_detect_route53_associate_vpc_with_hosted_zone_sql_columns       = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.hostedZoneId")  
}

benchmark "cloudtrail_logs_route53_detections" {
  title       = "CloudTrail Log Route53 Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's Route53 logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_route53_domain_transfered_to_another_account,
    detection.cloudtrail_logs_detect_route53_domain_transfer_lock_disabled_updates,
    detection.cloudtrail_logs_detect_route53_associate_vpc_with_hosted_zone,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/Route53"
  })
}

detection "cloudtrail_logs_detect_route53_domain_transfered_to_another_account" {
  title       = "Detect Route53 Domain Transfered to Another Account"
  description = "Detect Route53 domain transfered to another account to check for unauthorized domain transfers."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_route53_domain_transfered_to_another_account

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_route53_domain_transfer_lock_disabled_updates" {
  title       = "Detect Route53 Domain Transfer Lock Disabled"
  description = "Detect Route53 domain transfer lock disabled to check for unauthorized domain transfers."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_route53_domain_transfer_lock_disabled_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_route53_associate_vpc_with_hosted_zone" {
  title       = "Detect Route53 Associate VPC with Hosted Zone"
  description = "Detect Route53 associate VPC with hosted zone to check for unauthorized VPC associations."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_route53_associate_vpc_with_hosted_zone

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "cloudtrail_logs_detect_route53_domain_transfered_to_another_account" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_route53_domain_transfered_to_another_account_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'route53.amazonaws.com'
      and event_name = 'TransferDomainToAnotherAwsAccount'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_route53_domain_transfer_lock_disabled_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_route53_domain_transfered_to_another_account_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'route53.amazonaws.com'
      and event_name = 'DisableDomainTransferLock'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_route53_associate_vpc_with_hosted_zone" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_route53_associate_vpc_with_hosted_zone_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'route53.amazonaws.com'
      and event_name = 'AssociateVPCWithHostedZone'
      and error_code is null
    order by
      event_time desc;
  EOQ
}