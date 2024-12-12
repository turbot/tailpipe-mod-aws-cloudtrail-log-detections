locals {
  cloudtrail_logs_detect_vpc_updates_sql_columns                                  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.vpcId")
  cloudtrail_logs_detect_route_table_updates_sql_columns                         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.routeTableId")
}

benchmark "cloudtrail_logs_vpc_detections" {
  title       = "CloudTrail Log VPC Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's VPC logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_vpc_updates,
    detection.cloudtrail_logs_detect_route_table_updates,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/VPC"
  })
}

//TODO: Should the title include VPC?
detection "cloudtrail_logs_detect_route_table_updates" {
  title       = "Detect Route Tables Updates"
  description = "Detect route tables updates to check for changes in network configurations."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_route_table_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1048"
  })
}

detection "cloudtrail_logs_detect_vpc_updates" {
  title       = "Detect VPCs Updates"
  description = "Detect VPCs updates to check for changes in network configurations."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_vpc_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

query "cloudtrail_logs_detect_route_table_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_route_table_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('DisassociateRouteTable', 'DeleteRoute', 'DeleteRouteTable', 'ReplaceRoute', 'ReplaceRouteTableAssociation')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

//TODO: do we need all the event names? Check what might be helpful in detection
query "cloudtrail_logs_detect_vpc_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_vpc_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name in ('DeleteVpc', 'ModifyVpcAttribute', 'AcceptVpcPeeringConnection', 'DeleteVpcPeeringConnection', 'RejectVpcPeeringConnection', 'CreateVpcPeeringConnection', 'AttachClassicLinkVpc', 'DetachClassicLinkVpc', 'EnableVpcClassicLink', 'DisableVpcClassicLink')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}