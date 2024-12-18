locals {
  cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.groupId")
  # TODO: How to handle multiple possible resource paths? Split detection per event type?


  cloudtrail_logs_detect_ec2_gateway_updates_sql_columns             = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.internetGatewayId")
  cloudtrail_logs_detect_ec2_network_acl_updates_sql_columns         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.networkAclId")
  cloudtrail_logs_detect_rds_instance_pulicly_accessible_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.dbInstanceIdentifier")

  cloudtrail_logs_detect_ec2_full_network_packet_capture_updates_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "response_elements.trafficMirrorTargetId")

  // TODO: Get an array of flowLogIds. Need to extract it and convert it into a string?
  cloudtrail_logs_detect_ec2_flow_log_deletions_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.flowLogIds")

  cloudtrail_logs_detect_ec2_snapshot_updates_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.snapshotId")

  cloudtrail_logs_detect_ec2_ami_updates_sql_columns               = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_ec2_user_data_execution_sql_columns       = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userData")
  cloudtrail_logs_detect_security_group_allow_all_sql_columns      = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.groupId")
  cloudtrail_logs_detect_ec2_instance_updates_sql_columns          = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.instancesSet.items")
  cloudtrail_logs_detect_security_group_ipv4_allow_all_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.groupId")
  cloudtrail_logs_detect_security_group_ipv6_allow_all_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.groupId")
}

benchmark "cloudtrail_logs_ec2_detections" {
  title       = "EC2 Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's EC2 logs"
  type        = "detection"
  children = [
    detection.cloudtrail_logs_detect_ec2_ami_copy_cross_account,
    detection.cloudtrail_logs_detect_ec2_ami_import_cross_account,    
    detection.cloudtrail_logs_detect_ec2_ami_restore_tasks_cross_account,
    detection.cloudtrail_logs_detect_ec2_ami_store_tasks_external,
    detection.cloudtrail_logs_detect_ec2_flow_log_deletions,
    detection.cloudtrail_logs_detect_ec2_full_network_packet_capture_updates,
    detection.cloudtrail_logs_detect_ec2_gateway_updates,
    detection.cloudtrail_logs_detect_ec2_instances_with_launch_permission_changes,
    detection.cloudtrail_logs_detect_ec2_instances_with_source_dest_check_disabled,
    detection.cloudtrail_logs_detect_ec2_network_acl_updates,
    detection.cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates,
    detection.cloudtrail_logs_detect_ec2_snapshot_updates,
    detection.cloudtrail_logs_detect_security_group_ipv6_allow_all,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/EC2"
  })
}

detection "cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates" {
  title         = "Detect EC2 Security Groups Ingress/Egress Updates"
  description   = "Detect EC2 security groups ingress and egress rule updates to check for unauthorized VPC access or export of data."
  severity      = "medium"
  documentation = file("./detections/docs/cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates.md")
  query         = query.cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0005:T1562"
  })
}

detection "cloudtrail_logs_detect_ec2_network_acl_updates" {
  title       = "Detect EC2 Gateways Updates"
  description = "Detect EC2 gateways updates to check for changes in network configurations."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_ec2_network_acl_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "cloudtrail_logs_detect_ec2_gateway_updates" {
  title       = "Detect EC2 Gateways Updates"
  description = "Detect EC2 gateways updates to check for changes in network configurations."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_ec2_gateway_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "cloudtrail_logs_detect_ec2_full_network_packet_capture_updates" {
  title       = "Detect EC2 Full Network Packet Captures Updates"
  description = "Detect updates to EC2 full network packet capture configurations to identify potential misuse of Traffic Mirroring, which could be exploited to exfiltrate sensitive data from unencrypted internal traffic."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_ec2_full_network_packet_capture_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_ec2_flow_log_deletions" {
  title       = "Detect EC2 Flow Logs Deletions Updates"
  description = "Detect EC2 flow logs deletions updates to check for unauthorized changes."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_ec2_flow_log_deletions

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_ec2_snapshot_updates" {
  title       = "Detect EC2 Snapshots Updates"
  description = "Detect EC2 snapshots updates to check for unauthorized changes."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_ec2_snapshot_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_security_group_ipv4_allow_all" {
  title       = "Detect Security Groups Rule Modifications to Allow All Traffic to IPv4"
  description = "Detect when security group rules are modified to allow all traffic to IPv4."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_security_group_ipv4_allow_all

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

detection "cloudtrail_logs_detect_security_group_ipv6_allow_all" {
  title       = "Detect Security Group Rule Modification to Allow All Traffic to IPv6"
  description = "Detect when a security group rule is modified to allow all traffic to to IPv6."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_security_group_ipv6_allow_all

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

detection "cloudtrail_logs_detect_ec2_instances_with_source_dest_check_disabled" {
  title       = "Detect EC2 Source/Destination Check Disabled"
  description = "Identify attempts to disable the EC2 source/destination check, which could enable unauthorized traffic routing."
  severity    = "critical"
  query       = query.cloudtrail_logs_detect_ec2_instances_with_source_dest_check_disabled

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_logs_detect_ec2_instances_with_source_dest_check_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_instance_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'ModifyInstanceAttribute'
      and cast(request_parameters ->> 'attribute' as text) = 'sourceDestCheck'
      and cast(request_parameters ->> 'value' as text) = 'false'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_ec2_instances_with_launch_permission_changes" {
  title       = "Detect EC2 Launch Permission Changes"
  description = "Identify changes to EC2 instance or AMI launch permissions, potentially granting unauthorized access."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_ec2_instances_with_launch_permission_changes

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1078"
  })
}

query "cloudtrail_logs_detect_ec2_instances_with_launch_permission_changes" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_instance_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('ModifyInstanceAttribute', 'ResetImageAttribute')
      and cast(request_parameters ->> 'attribute' as text) = 'launchPermission'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('AuthorizeSecurityGroupEgress', 'AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'RevokeSecurityGroupIngress')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_ec2_gateway_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_gateway_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('DeleteCustomerGateway', 'AttachInternetGateway', 'DeleteInternetGateway', 'DetachInternetGateway')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_ec2_network_acl_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_network_acl_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('DeleteNetworkAcl', 'DeleteNetworkAclEntry', 'ReplaceNetworkAclEntry', 'ReplaceNetworkAclAssociation')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_ec2_full_network_packet_capture_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_full_network_packet_capture_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('CreateTrafficMirrorTarget', 'CreateTrafficMirrorFilter', 'CreateTrafficMirrorSession', 'CreateTrafficMirrorFilterRule')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_ec2_snapshot_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_snapshot_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('DeleteSnapshot', 'ModifySnapshotAttribute')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_ec2_flow_log_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_flow_log_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DeleteFlowLogs'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_security_group_ipv4_allow_all" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_security_group_ipv4_allow_all_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress')
      and cast(request_parameters -> 'ipPermissions' as text) like '%0.0.0.0/0%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_security_group_ipv6_allow_all" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_security_group_ipv6_allow_all_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress')
      and cast(request_parameters -> 'ipPermissions' as text) like '%::/0%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_ec2_ami_copy_cross_account" {
  title       = "Detect Cross-Account EC2 AMI Copy Events"
  description = "Identify events where EC2 AMIs are copied across accounts, which could indicate unauthorized duplication."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_ec2_ami_copy_cross_account

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1020"
  })
}

query "cloudtrail_logs_detect_ec2_ami_copy_cross_account" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_ami_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('CopyImage', 'CopyFpgaImage')
      and user_identity ->> 'accountId' != request_parameters ->> 'SourceAccountId'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_ec2_ami_restore_tasks_cross_account" {
  title       = "Detect Cross-Account EC2 AMI Restore Tasks"
  description = "Identify events where restore image tasks involve resources from different accounts, potentially indicating data recovery or unauthorized restoration."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_ec2_ami_restore_tasks_cross_account

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0007:T1078"
  })
}

query "cloudtrail_logs_detect_ec2_ami_restore_tasks_cross_account" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_ami_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'CreateRestoreImageTask'
      and user_identity ->> 'accountId' != request_parameters ->> 'OwnerId'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_ec2_ami_store_tasks_external" {
  title       = "Detect EC2 AMI Store Tasks in External Locations"
  description = "Identify events where EC2 AMIs are stored in external or unapproved destinations, potentially indicating data exfiltration."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_ec2_ami_store_tasks_external

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1537"
  })
}

query "cloudtrail_logs_detect_ec2_ami_store_tasks_external" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_ami_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'CreateStoreImageTask'
      and user_identity ->> 'accountId' != request_parameters ->> 'OwnerId'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_ec2_ami_import_cross_account" {
  title       = "Detect Cross-Account EC2 AMI Import Events"
  description = "Identify events where AMIs are imported from external accounts, potentially introducing unauthorized or untrusted images."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_ec2_ami_import_cross_account

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1577"
  })
}

query "cloudtrail_logs_detect_ec2_ami_import_cross_account" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_ami_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'ImportImage'
      and user_identity ->> 'accountId' != request_parameters ->> 'OwnerId'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}
