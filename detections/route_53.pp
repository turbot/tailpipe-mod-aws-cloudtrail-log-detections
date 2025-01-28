locals {
  route_53_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/Route53"
  })
}

benchmark "route_53_detections" {
  title       = "Route 53 Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for Route 53 events."
  type        = "detection"
  children    = [
    detection.route_53_domain_transfer_lock_disabled,
    detection.route_53_domain_transferred,
    detection.route_53_hosted_zone_associated_with_vpc,
  ]

  tags = merge(local.route_53_common_tags, {
    type    = "Benchmark"
  })
}

detection "route_53_domain_transferred" {
  title           = "Route 53 Domain Transferred"
  description     = "Detect when a Route 53 domain was transferred to another AWS account to check for potential risks of unauthorized transfers, which could lead to domain hijacking, service disruption, or malicious use of web infrastructure."
  documentation   = file("./detections/docs/route_53_domain_transferred.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.route_53_domain_transferred

  tags = merge(local.route_53_common_tags, {
    mitre_attack_ids = "TA0040:T1531"
  })
}

detection "route_53_domain_transfer_lock_disabled" {
  title           = "Route 53 Domain Transfer Lock Disabled"
  description     = "Detect when the transfer lock on a Route 53 domain was disabled to check for potential risks of unauthorized domain transfers, which could result in loss of control, domain hijacking, service disruptions, or malicious use of the domain."
  documentation   = file("./detections/docs/route_53_domain_transfer_lock_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.route_53_domain_transfer_lock_disabled

  tags = merge(local.route_53_common_tags, {
    mitre_attack_ids = "TA0040:T1531"
  })
}

detection "route_53_hosted_zone_associated_with_vpc" {
  title           = "Route 53 Hosted Zone Associated with VPC"
  description     = "Detect when a Route 53 hosted zone was associated with a VPC to check for potential risks of unauthorized associations, which could expose DNS records to unintended networks, enabling lateral movement, unauthorized access, or DNS-based attacks."
  documentation   = file("./detections/docs/route_53_hosted_zone_associated_with_vpc.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.route_53_hosted_zone_associated_with_vpc

  tags = merge(local.route_53_common_tags, {
    mitre_attack_ids = "TA0003:T1078"
  })
}

query "route_53_domain_transferred" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_domain_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'route_53.amazonaws.com'
      and event_name = 'TransferDomainToAnotherAwsAccount'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "route_53_domain_transfer_lock_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_domain_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'route_53.amazonaws.com'
      and event_name = 'DisableDomainTransferLock'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "route_53_hosted_zone_associated_with_vpc" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_hosted_zone_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'route_53.amazonaws.com'
      and event_name = 'AssociateVPCWithHostedZone'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
