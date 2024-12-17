locals {
  cloudtrail_log_detection_vpc_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/VPC"
  })

  cloudtrail_logs_detect_vpc_deletions_sql_columns                         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.vpcId")
  cloudtrail_logs_detect_vpcs_with_classic_link_enabled_sql_columns        = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.vpcId")
  cloudtrail_logs_detect_vpc_peering_connection_deletions_sql_columns       = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.vpcId")
  cloudtrail_logs_detect_vpc_route_table_updates_sql_columns                = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.routeTableId")
  cloudtrail_logs_detect_vpc_route_table_deletions_sql_columns              = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.routeTableId")
  cloudtrail_logs_detect_vpc_route_table_route_deletions_sql_columns        = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.routeTableId")
  cloudtrail_logs_detect_vpc_route_table_route_disassociations_sql_columns  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.routeTableId")
  cloudtrail_logs_detect_vpc_route_table_replace_associations_sql_columns   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.routeTableId")
}

benchmark "cloudtrail_logs_vpc_detections" {
  title       = "VPC Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for VPC events."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_vpc_deletions,
    detection.cloudtrail_logs_detect_vpc_peering_connection_deletions,
    detection.cloudtrail_logs_detect_vpc_route_table_deletions,
    detection.cloudtrail_logs_detect_vpc_route_table_replace_associations,
    detection.cloudtrail_logs_detect_vpc_route_table_route_deletions,
    detection.cloudtrail_logs_detect_vpc_route_table_route_disassociations,
    detection.cloudtrail_logs_detect_vpcs_with_classic_link_enabled,
  ]

  tags = merge(local.cloudtrail_log_detection_vpc_common_tags, {
    type    = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_vpc_route_table_deletions" {
  title       = "Detect VPC Route Tables Deletions"
  description = "Detect route tables deletions to check for changes in network configurations."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_vpc_route_table_deletions

  tags = merge(local.cloudtrail_log_detection_vpc_common_tags, {
    mitre_attack_ids = "TA0040:T1565.003, TA0005:T1070"
  })
}

detection "cloudtrail_logs_detect_vpc_route_table_route_deletions" {
  title       = "Detect VPC Route Table Route Deletions"
  description = "Detect when routes are deleted from VPC route tables, which could disrupt network traffic, impair defenses, or facilitate unauthorized traffic manipulation."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_vpc_route_table_route_deletions

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1070, TA0040:T1565.003"
  })
}

detection "cloudtrail_logs_detect_vpc_route_table_route_disassociations" {
  title       = "Detect VPC Route Table Disassociations"
  description = "Detect when VPC route tables are disassociated from subnets, which could disrupt network routing or facilitate malicious traffic manipulation."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_vpc_route_table_route_disassociations

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1070, TA0040:T1565.003"
  })
}

detection "cloudtrail_logs_detect_vpc_route_table_replace_associations" {
  title       = "Detect VPC Route Table Replace Associations"
  description = "Detect when a VPC route table association is replaced, which could manipulate network traffic, bypass security controls, or disrupt connectivity."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_vpc_route_table_replace_associations

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1070, TA0040:T1565.003"
  })
}

detection "cloudtrail_logs_detect_vpc_deletions" {
  title       = "Detect VPC Deletions"
  description = "Detect when a VPC is deleted, which can disrupt network infrastructure and impair defenses."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_vpc_deletions

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1565, TA0005:T1070"
  })
}

detection "cloudtrail_logs_detect_vpcs_with_classic_link_enabled" {
  title       = "Detect VPC ClassicLink Enables"
  description = "Detect when VPC ClassicLink is enabled, which could increase the attack surface by allowing connections to legacy EC2-Classic instances."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_vpcs_with_classic_link_enabled

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1078, TA0005:T1562.001"
  })
}

detection "cloudtrail_logs_detect_vpc_peering_connection_deletions" {
  title       = "Detect VPC Peering Connection Deletions"
  description = "Detect when a VPC peering connection is deleted, which could disrupt network communication between VPCs or impair defenses."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_vpc_peering_connection_deletions

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1070, TA0040:T1565.003"
  })
}

query "cloudtrail_logs_detect_vpc_route_table_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_vpc_route_table_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DeleteRouteTable'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_vpc_route_table_route_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_vpc_route_table_route_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DeleteRoute'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_vpc_route_table_route_disassociations" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_vpc_route_table_route_disassociations_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DisassociateRouteTable'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_vpc_route_table_replace_associations" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_vpc_route_table_replace_associations_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'ReplaceRouteTableAssociation'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_vpc_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_vpc_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'DeleteVpc'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_vpcs_with_classic_link_enabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_vpcs_with_classic_link_enabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'EnableVpcClassicLink'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_vpc_peering_connection_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_vpc_peering_connection_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'DeleteVpcPeeringConnection'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}
