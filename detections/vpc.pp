locals {
  vpc_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/VPC"
  })
}

benchmark "vpc_detections" {
  title       = "VPC Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for VPC events."
  type        = "detection"
  children = [
    detection.vpc_internet_gateway_added_to_public_route_table,
    detection.vpc_created,
    detection.vpc_deleted,
    detection.vpc_flow_log_deleted,
    detection.vpc_network_acl_updated,
    detection.vpc_peering_connection_deleted,
    detection.vpc_route_table_deleted,
    detection.vpc_route_table_association_replaced,
    detection.vpc_route_table_route_deleted,
    detection.vpc_route_table_route_disassociated,
    detection.vpc_security_group_deleted,
    detection.vpc_security_group_ingress_egress_rule_updated,
    detection.vpc_security_group_ingress_egress_rule_authorized_to_allow_all,
    detection.vpc_nacl_rule_updated_with_allow_public_access,
    detection.vpc_classic_link_enabled,
    detection.vpc_internet_gateway_detached
  ]

  tags = merge(local.vpc_common_tags, {
    type = "Benchmark"
  })
}

detection "vpc_security_group_deleted" {
  title           = "VPC Security Group Deleted"
  description     = "Detect when a VPC security group was deleted to check for unauthorized changes, which could expose resources to unregulated traffic or disrupt network security configurations."
  documentation   = file("./detections/docs/vpc_security_group_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.vpc_security_group_deleted

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1070,TA0002:T1059.009"
  })
}

query "vpc_security_group_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_network_security_group_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DeleteSecurityGroup'
      ${local.detection_sql_where_conditions}
    order by event_time desc;
  EOQ
}

detection "vpc_internet_gateway_added_to_public_route_table" {
  title           = "VPC Internet Gateway Added to Public Route Table"
  description     = "Detect when a VPC route table was created to include a route to 0.0.0.0/0 via an Internet Gateway, potentially exposing resources to public access and increasing the risk of unauthorized access or data exfiltration."
  documentation   = file("./detections/docs/vpc_internet_gateway_added_to_public_route_table.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.vpc_internet_gateway_added_to_public_route_table

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0040:T1578"
  })
}

query "vpc_internet_gateway_added_to_public_route_table" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_network_route_table_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'CreateRoute'
      and (request_parameters ->> 'destinationCidrBlock') = '0.0.0.0/0'
      and (request_parameters ->> 'gatewayId') like 'igw-%'
      ${local.detection_sql_where_conditions}
    order by event_time desc;
  EOQ
}

detection "vpc_route_table_deleted" {
  title           = "VPC Route Table Deleted"
  description     = "Detect when a VPC route table was deleted to check for changes in network configurations, which could disrupt routing, impair connectivity, or impact security posture."
  documentation   = file("./detections/docs/vpc_route_table_deleted.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.vpc_route_table_deleted

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0040:T1565.003,TA0005:T1070"
  })
}

detection "vpc_route_table_route_deleted" {
  title           = "VPC Route Table Route Deleted"
  description     = "Detect when a route was deleted from a VPC route table, which could disrupt network traffic, impair defenses, or facilitate unauthorized traffic manipulation."
  documentation   = file("./detections/docs/vpc_route_table_route_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.vpc_route_table_route_deleted

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1070,TA0040:T1565.003"
  })
}

detection "vpc_route_table_route_disassociated" {
  title           = "VPC Route Table Route Disassociated"
  description     = "Detect when a route was disassociated from a VPC route table, potentially disrupting network routing or facilitating malicious traffic manipulation."
  documentation   = file("./detections/docs/vpc_route_table_route_disassociated.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.vpc_route_table_route_disassociated

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1070,TA0040:T1565.003"
  })
}

detection "vpc_route_table_association_replaced" {
  title           = "VPC Route Table Association Replaced"
  description     = "Detect when a VPC route table association was replaced, which could manipulate network traffic, bypass security controls, or disrupt connectivity."
  documentation   = file("./detections/docs/vpc_route_table_association_replaced.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.vpc_route_table_association_replaced

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1070,TA0040:T1565.003"
  })
}

detection "vpc_created" {
  title           = "VPC Created"
  description     = "Detect when a VPC was created, which could indicate unauthorized infrastructure setup. Such actions may be used to isolate malicious activities, evade monitoring, or stage resources for lateral movement and data exfiltration. Monitoring VPC creation helps ensure compliance with security policies and detects potential misuse of cloud resources."
  documentation   = file("./detections/docs/vpc_created.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.vpc_created

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1562.003"
  })
}

detection "vpc_deleted" {
  title           = "VPC Deleted"
  description     = "Detect when a VPC was deleted to check for disruptions to network infrastructure, which could impair defenses, disrupt monitoring, and impact overall connectivity and security."
  documentation   = file("./detections/docs/vpc_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.vpc_deleted

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0040:T1565,TA0005:T1070"
  })
}

detection "vpc_classic_link_enabled" {
  title           = "VPC Classic Link Enabled"
  description     = "Detect when VPC ClassicLink was enabled, as it could increase the attack surface by allowing connections to legacy EC2-Classic instances, potentially exposing resources to unauthorized access or misconfigurations."
  documentation   = file("./detections/docs/vpc_classic_link_enabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.vpc_classic_link_enabled

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0003:T1078,TA0005:T1562.001"
  })
}

detection "vpc_peering_connection_deleted" {
  title           = "VPC Peering Connection Deleted"
  description     = "Detect when a VPC peering connection was deleted to check for potential disruptions to network communication, which could impair connectivity, defenses, or compliance with security policies."
  documentation   = file("./detections/docs/vpc_peering_connection_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.vpc_peering_connection_deleted

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1070,TA0040:T1565.003"
  })
}

detection "vpc_security_group_ingress_egress_rule_updated" {
  title           = "VPC Security Group Ingress/Egress Rule Updated"
  description     = "Detect when a VPC security group's ingress or egress rule was updated to check for unauthorized access or potential data exfiltration."
  documentation   = file("./detections/docs/vpc_security_group_ingress_egress_rule_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.vpc_security_group_ingress_egress_rule_updated

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0005:T1562"
  })
}

detection "vpc_network_acl_updated" {
  title           = "VPC Network ACL Updated"
  description     = "Detect when a VPC Network ACL was updated to check for unauthorized changes in network configurations, which could allow or restrict traffic unexpectedly and impact security posture."
  documentation   = file("./detections/docs/vpc_network_acl_updated.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.vpc_network_acl_updated

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "vpc_flow_log_deleted" {
  title           = "VPC Flow Log Deleted"
  description     = "Detect when a VPC flow log was deleted to check for unauthorized changes, which may impact network monitoring and hinder forensic investigations."
  documentation   = file("./detections/docs/vpc_flow_log_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.vpc_flow_log_deleted

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

detection "vpc_security_group_ingress_egress_rule_authorized_to_allow_all" {
  title           = "VPC Security Group Ingress/Egress Rule Authorized to Allow All"
  description     = "Detect when a VPC security group's ingress or egress rule was authorized to allow all IPv4 or IPv6 traffic, potentially exposing resources to unauthorized access or malicious activity."
  documentation   = file("./detections/docs/vpc_security_group_ingress_egress_rule_authorized_to_allow_all.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.vpc_security_group_ingress_egress_rule_authorized_to_allow_all

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

query "vpc_route_table_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_network_route_table_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DeleteRouteTable'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "vpc_route_table_route_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_network_route_table_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DeleteRoute'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "vpc_route_table_route_disassociated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_network_route_table_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DisassociateRouteTable'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "vpc_route_table_association_replaced" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_network_route_table_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'ReplaceRouteTableAssociation'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "vpc_created" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_vpc_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'CreateVpc'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "vpc_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_vpc_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DeleteVpc'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "vpc_classic_link_enabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_vpc_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'EnableVpcClassicLink'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "vpc_peering_connection_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_vpc_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DeleteVpcPeeringConnection'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "vpc_flow_log_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_network_flow_log_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DeleteFlowLogs'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "vpc_security_group_ingress_egress_rule_authorized_to_allow_all" {
  sql = <<-EOQ
    with permissions as (
      select 
        *,
        (item -> 'unnest') as ip_permission
      from
        aws_cloudtrail_log,
        unnest(from_json((request_parameters ->> 'ipPermissions' -> 'items'), '["JSON"]')) as item
      where
        event_source = 'ec2.amazonaws.com'
        and event_name in ('AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress')
        ${local.detection_sql_where_conditions}
    ),
    ipv4 as (
      select
        *
      from
        permissions, 
        unnest(from_json((ip_permission -> 'ipRanges' -> 'items'), '["JSON"]')) as item,
      where
        (item -> 'unnest' ->> 'cidrIp') = '0.0.0.0/0'
    ),
    ipv6 as (
      select
        *
      from
        permissions, 
        unnest(from_json((ip_permission -> 'ipv6Ranges' -> 'items'), '["JSON"]')) as item,
      where
        (item -> 'unnest' ->> 'cidrIpv6') = '::/0'
    ),
    all_ip as (
      select * from ipv4
      union all
      select * from ipv6
     ) 
    select
      ${local.detection_sql_resource_column_request_parameters_network_security_group_id}
    from
      all_ip
    order by
      event_time desc;
  EOQ
}

query "vpc_security_group_ingress_egress_rule_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_network_security_group_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('AuthorizeSecurityGroupEgress', 'AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'RevokeSecurityGroupIngress')
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "vpc_network_acl_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_network_acl_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('DeleteNetworkAclEntry', 'ReplaceNetworkAclEntry', 'ReplaceNetworkAclAssociation')
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "vpc_nacl_rule_updated_with_allow_public_access" {
  title           = "VPC Network ACL Rule Updated With Allow Public Access"
  description     = "Detect when a VPC Network ACL rule was created or updated to allow public access (0.0.0.0/0), potentially exposing resources to unauthorized access or disrupting security controls."
  documentation   = file("./detections/docs/vpc_nacl_rule_updated_with_allow_public_access.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.vpc_nacl_rule_updated_with_allow_public_access

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0040:T1562.004"
  })
}

query "vpc_nacl_rule_updated_with_allow_public_access" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_network_acl_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('CreateNetworkAclEntry', 'ReplaceNetworkAclEntry')
      and (request_parameters ->> 'ruleAction') = 'allow'
      and ((request_parameters ->> 'cidrBlock') = '0.0.0.0/0' or (request_parameters ->> 'ipv6CidrBlock') = '::/0')
      ${local.detection_sql_where_conditions}
    order by 
      event_time desc;
  EOQ
}

detection "vpc_internet_gateway_detached" {
  title           = "VPC Internet Gateway Detached"
  description     = "Detect when an Internet Gateway was detached from a VPC, potentially disrupting security configurations or impairing network defenses, leading to isolation of critical resources and interruption of connectivity."
  documentation   = file("./detections/docs/vpc_internet_gateway_detached.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.vpc_internet_gateway_detached

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0040:T1562.004" # Disable or Modify Firewall
  })
}

query "vpc_internet_gateway_detached" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_vpc_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DetachInternetGateway'
      ${local.detection_sql_where_conditions}
    order by 
      event_time desc;
  EOQ
}

