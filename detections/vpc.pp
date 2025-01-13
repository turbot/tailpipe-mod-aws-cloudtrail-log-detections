locals {
  vpc_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/VPC"
  })

  detect_vpc_creations_sql_columns                                   = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.vpcId')")
  detect_vpc_deletions_sql_columns                                   = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.vpcId')")
  detect_vpc_full_network_packet_capture_updates_sql_columns         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(response_elements, '$.trafficMirrorTargetId')")
  detect_vpc_network_acl_updates_sql_columns                         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.networkAclId')")
  detect_vpc_peering_connection_deletions_sql_columns                = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.vpcId')")
  detect_vpc_route_table_deletions_sql_columns                       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.routeTableId')")
  detect_vpc_route_table_replace_associations_sql_columns            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.routeTableId')")
  detect_vpc_route_table_route_deletions_sql_columns                 = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.routeTableId')")
  detect_vpc_route_table_route_disassociations_sql_columns           = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.routeTableId')")
  detect_vpc_route_table_updates_sql_columns                         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.routeTableId')")
  detect_vpc_security_group_ingress_egress_updates_sql_columns       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.groupId')")
  detect_vpc_security_group_ipv4_allow_all_sql_columns               = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.groupId')")
  detect_vpc_security_group_ipv6_allow_all_sql_columns               = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.groupId')")
  detect_vpcs_with_classic_link_enabled_sql_columns                  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.vpcId')")
  detect_vpc_flow_log_deletions_sql_columns                          = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.flowLogIds')")
  detect_traffic_mirror_targets_with_internet_facing_nlb_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.trafficMirrorTargetId')")
  detect_vpcs_with_internet_gateway_detachments_sql_columns          = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.vpcId')")
  detect_vpc_network_acls_with_deny_all_rule_deletions_sql_columns   = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.networkAclId')")
  detect_vpcs_with_nacl_association_replacements_sql_columns         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.associationId')")
  detect_internet_gateways_added_to_public_route_tables_sql_columns  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.routeTableId')")
  detect_vpc_security_group_deletions_sql_columns                    = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.groupId')")
}

benchmark "vpc_detections" {
  title       = "VPC Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for VPC events."
  type        = "detection"
  children = [
    detection.detect_vpc_creations,
    detection.detect_vpc_deletions,
    detection.detect_vpc_flow_log_deletions,
    detection.detect_vpc_security_group_deletions,
    detection.detect_vpcs_with_internet_gateway_detachments,
    detection.detect_vpcs_with_nacl_association_replacements,
    detection.detect_vpc_peering_connection_deletions,
    detection.detect_vpc_route_table_deletions,
    detection.detect_vpc_route_table_replace_associations,
    detection.detect_vpc_route_table_route_deletions,
    detection.detect_vpc_route_table_route_disassociations,
    detection.detect_vpc_security_group_ingress_egress_updates,
    detection.detect_vpc_security_group_ipv4_allow_all,
    detection.detect_vpc_security_group_ipv6_allow_all,
    detection.detect_vpcs_with_classic_link_enabled,
    detection.detect_traffic_mirror_targets_with_internet_facing_nlb,
    detection.detect_internet_gateways_added_to_public_route_tables,
    detection.detect_vpc_network_acls_with_deny_all_rule_deletions,
  ]

  tags = merge(local.vpc_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_vpc_security_group_deletions" {
  title           = "Detect VPC Security Group Deletions"
  description     = "Detect VPC security group deletions to check for unauthorized changes."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_vpc_security_group_deletions

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1070,TA0002:T1059.009"
  })
}

query "detect_vpc_security_group_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_vpc_security_group_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DeleteSecurityGroup'
      ${local.detection_sql_where_conditions}
    order by event_time desc;
  EOQ
}

detection "detect_internet_gateways_added_to_public_route_tables" {
  title           = "Detect Internet Gateways Added to Public Route Tables"
  description     = "Detect when a route table is updated to add a route to 0.0.0.0/0 via an Internet Gateway, potentially exposing resources to public access."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_internet_gateways_added_to_public_route_tables

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0040:T1578"
  })
}

query "detect_internet_gateways_added_to_public_route_tables" {
  sql = <<-EOQ
    select
      ${local.detect_internet_gateways_added_to_public_route_tables_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'CreateRoute'
      and json_extract_string(request_parameters, '$.destinationCidrBlock') = '0.0.0.0/0'
      and json_extract_string(request_parameters, '$.gatewayId') like 'igw-%'
      ${local.detection_sql_where_conditions}
    order by event_time desc;
  EOQ
}

detection "detect_vpc_route_table_deletions" {
  title           = "Detect VPC Route Tables Deletions"
  description     = "Detect route tables deletions to check for changes in network configurations."
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_vpc_route_table_deletions

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0040:T1565.003, TA0005:T1070"
  })
}

detection "detect_vpc_route_table_route_deletions" {
  title           = "Detect VPC Route Table Route Deletions"
  description     = "Detect when routes are deleted from VPC route tables, which could disrupt network traffic, impair defenses, or facilitate unauthorized traffic manipulation."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_vpc_route_table_route_deletions

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1070, TA0040:T1565.003"
  })
}

detection "detect_vpc_route_table_route_disassociations" {
  title           = "Detect VPC Route Table Disassociations"
  description     = "Detect when VPC route tables are disassociated from subnets, which could disrupt network routing or facilitate malicious traffic manipulation."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_vpc_route_table_route_disassociations

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1070, TA0040:T1565.003"
  })
}

detection "detect_vpc_route_table_replace_associations" {
  title           = "Detect VPC Route Table Replace Associations"
  description     = "Detect when a VPC route table association is replaced, which could manipulate network traffic, bypass security controls, or disrupt connectivity."
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_vpc_route_table_replace_associations

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1070, TA0040:T1565.003"
  })
}

detection "detect_vpc_creations" {
  title           = "Detect VPC Creations"
  description     = "Detect when a VPC is created, to check for unauthorized infrastructure setup, which could be used to isolate malicious activities, evade monitoring, or stage resources for lateral movement and data exfiltration. Monitoring VPC creation ensures compliance with security policies and detects potential misuse of cloud resources."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_vpc_deletions

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1562.003"
  })
}

detection "detect_vpc_deletions" {
  title           = "Detect VPC Deletions"
  description     = "Detect when a VPC is deleted, which can disrupt network infrastructure and impair defenses."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_vpc_deletions

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0040:T1565, TA0005:T1070"
  })
}

detection "detect_vpcs_with_classic_link_enabled" {
  title           = "Detect VPC ClassicLink Enabled"
  description     = "Detect when VPC ClassicLink is enabled, which could increase the attack surface by allowing connections to legacy EC2-Classic instances."
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_vpcs_with_classic_link_enabled

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0003:T1078, TA0005:T1562.001"
  })
}

detection "detect_vpc_peering_connection_deletions" {
  title           = "Detect VPC Peering Connection Deletions"
  description     = "Detect when a VPC peering connection is deleted, which could disrupt network communication between VPCs or impair defenses."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_vpc_peering_connection_deletions

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1070, TA0040:T1565.003"
  })
}

detection "detect_vpc_security_group_ingress_egress_updates" {
  title           = "Detect VPC Security Groups Ingress/Egress Updates"
  description     = "Detect VPC security groups ingress and egress rule updates to check for unauthorized VPC access or export of data."
  severity        = "medium"
  display_columns = local.detection_display_columns
  documentation   = file("./detections/docs/detect_vpc_security_group_ingress_egress_updates.md")
  query           = query.detect_vpc_security_group_ingress_egress_updates

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0005:T1562"
  })
}

detection "detect_vpc_network_acl_updates" {
  title           = "Detect VPC Network ACL Updates"
  description     = "Detect VPC gateways updates to check for changes in network configurations."
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_vpc_network_acl_updates

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "detect_vpc_flow_log_deletions" {
  title           = "Detect VPC Flow Logs Deletions"
  description     = "Detect VPC flow logs deletions updates to check for unauthorized changes."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_vpc_flow_log_deletions

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

detection "detect_vpc_security_group_ipv4_allow_all" {
  title           = "Detect Security Groups Rule Modifications to Allow All Traffic to IPv4"
  description     = "Detect when security group rules are modified to allow all traffic to IPv4."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_vpc_security_group_ipv4_allow_all

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

detection "detect_vpc_security_group_ipv6_allow_all" {
  title           = "Detect Security Group Rule Modification to Allow All Traffic to IPv6"
  description     = "Detect when a security group rule is modified to allow all traffic to to IPv6."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_vpc_security_group_ipv6_allow_all

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

query "detect_vpc_route_table_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_vpc_route_table_deletions_sql_columns}
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

query "detect_vpc_route_table_route_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_vpc_route_table_route_deletions_sql_columns}
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

query "detect_vpc_route_table_route_disassociations" {
  sql = <<-EOQ
    select
      ${local.detect_vpc_route_table_route_disassociations_sql_columns}
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

query "detect_vpc_route_table_replace_associations" {
  sql = <<-EOQ
    select
      ${local.detect_vpc_route_table_replace_associations_sql_columns}
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

query "detect_vpc_creations" {
  sql = <<-EOQ
    select
      ${local.detect_vpc_creations_sql_columns}
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

query "detect_vpc_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_vpc_deletions_sql_columns}
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

query "detect_vpcs_with_classic_link_enabled" {
  sql = <<-EOQ
    select
      ${local.detect_vpcs_with_classic_link_enabled_sql_columns}
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

query "detect_vpc_peering_connection_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_vpc_peering_connection_deletions_sql_columns}
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

query "detect_vpc_flow_log_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_vpc_flow_log_deletions_sql_columns}
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

query "detect_vpc_security_group_ipv4_allow_all" {
  sql = <<-EOQ
    select
      ${local.detect_vpc_security_group_ipv4_allow_all_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress')
      and json_extract_string(request_parameters, '$.ipPermissions') like '%0.0.0.0/0%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "detect_vpc_security_group_ipv6_allow_all" {
  sql = <<-EOQ
    select
      ${local.detect_vpc_security_group_ipv6_allow_all_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress')
      and json_extract_string(request_parameters, '$.ipPermissions') like '%::/0%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}


query "detect_vpc_security_group_ingress_egress_updates" {
  sql = <<-EOQ
    select
      ${local.detect_vpc_security_group_ingress_egress_updates_sql_columns}
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

query "detect_vpc_network_acl_updates" {
  sql = <<-EOQ
    select
      ${local.detect_vpc_network_acl_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('DeleteNetworkAcl', 'DeleteNetworkAclEntry', 'ReplaceNetworkAclEntry', 'ReplaceNetworkAclAssociation')
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_vpcs_with_nacl_association_replacements" {
  title           = "Detect VPCs with Network ACL Association Replacements"
  description     = "Detect when a Network ACL association is replaced, potentially redirecting traffic through a different ACL with weaker security rules, leading to unauthorized access."
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_vpcs_with_nacl_association_replacements

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0040:T1562.004"
  })
}

query "detect_vpcs_with_nacl_association_replacements" {
  sql = <<-EOQ
    select
      ${local.detect_vpcs_with_nacl_association_replacements_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'ReplaceNetworkAclAssociation'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_vpc_network_acls_with_deny_all_rule_deletions" {
  title           = "Detect Network ACLs with Deny-All Rule Deletions"
  description     = "Detect when Network ACL rules that block all traffic (deny all rules) are deleted, potentially allowing unrestricted traffic and exposing resources to unauthorized access."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_vpc_network_acls_with_deny_all_rule_deletions

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0040:T1562.004"
  })
}

query "detect_vpc_network_acls_with_deny_all_rule_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_vpc_network_acls_with_deny_all_rule_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DeleteNetworkAclEntry'
      and json_extract_string(request_parameters, '$.ruleAction') = 'deny'
      ${local.detection_sql_where_conditions}
    order by 
      event_time desc;
  EOQ
}

detection "detect_public_access_granted_to_nacl" {
  title           = "Detect Public Access Granted in Network ACL Rules"
  description     = "Detect when Network ACL rules are created or modified to allow public access (0.0.0.0/0), potentially exposing resources to unauthorized access or disrupting security controls."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_public_access_granted_to_nacl

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0040:T1562.004"
  })
}

query "detect_public_access_granted_to_nacl" {
  sql = <<-EOQ
    select
      ${local.detect_vpc_network_acl_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('CreateNetworkAclEntry', 'ReplaceNetworkAclEntry')
      and json_extract_string(request_parameters, '$.cidrBlock') = '0.0.0.0/0'
      ${local.detection_sql_where_conditions}
    order by 
      event_time desc;
  EOQ
}

detection "detect_traffic_mirror_targets_with_internet_facing_nlb" {
  title           = "Detect Traffic Mirroring Targets with Internet-Facing Network Load Balancer"
  description     = "Detect when a Traffic Mirroring target is created with an internet-facing Network Load Balancer, potentially exposing sensitive traffic to unauthorized access."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_traffic_mirror_targets_with_internet_facing_nlb

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0010:T1020"
  })
}

query "detect_traffic_mirror_targets_with_internet_facing_nlb" {
  sql = <<-EOQ
    select
      ${local.detect_traffic_mirror_targets_with_internet_facing_nlb_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'CreateTrafficMirrorTarget'
      and json_extract_string(request_parameters, '$.networkLoadBalancerArn') is not null
      and json_extract_string(request_parameters, '$.scheme') = 'internet-facing'
      and json_extract_string(user_identity, '$.type') != 'AssumedRole'
      and json_extract_string(user_identity, '$.type') != 'AWSService'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_vpcs_with_internet_gateway_detachments" {
  title           = "Detect VPCs with Internet Gateway Detachments"
  description     = "Detect when an Internet Gateway is detached from a VPC, potentially disrupting security configurations or impairing network defenses, leading to isolation of critical resources."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_vpcs_with_internet_gateway_detachments

  tags = merge(local.vpc_common_tags, {
    mitre_attack_ids = "TA0040:T1562.004" # Disable or Modify Firewall
  })
}

query "detect_vpcs_with_internet_gateway_detachments" {
  sql = <<-EOQ
    select
      ${local.detect_vpcs_with_internet_gateway_detachments_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DetachInternetGateway'
      and json_extract_string(user_identity, '$.type') != 'AssumedRole'
      and json_extract_string(user_identity, '$.type') != 'AWSService'
      ${local.detection_sql_where_conditions}
    order by 
      event_time desc;
  EOQ
}

