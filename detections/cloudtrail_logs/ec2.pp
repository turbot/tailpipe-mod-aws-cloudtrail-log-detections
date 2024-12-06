benchmark "cloudtrail_logs_ec2_detections" {
  title       = "CloudTrail Log EC2 Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's EC2 logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_ec2_gateway_updates,
    detection.cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates,
    detection.cloudtrail_logs_detect_ec2_full_network_packet_capture_updates,
    detection.cloudtrail_logs_detect_ec2_flow_logs_deletion_updates,
    detection.cloudtrail_logs_detect_ec2_snapshot_updates,
    detection.cloudtrail_logs_detect_ec2_ami_updates,
    detection.cloudtrail_logs_detect_ec2_network_acl_updates,
    detection.cloudtrail_logs_detect_stopped_ec2_instances,
  ]
}

detection "cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates" {
  title       = "Detect EC2 Security Group Ingress/Egress Updates"
  description = "Detect EC2 security group ingress and egress rule updates to check for unauthorized VPC access or export of data."
  severity    = "medium"
  documentation = file("./detections/docs/cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates.md")
  query       = query.cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0005:T1562"
  })
}

detection "cloudtrail_logs_detect_ec2_network_acl_updates" {
  title       = "Detect EC2 Gateway Updates"
  description = "Detect EC2 gateway updates to check for changes in network configurations."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_ec2_network_acl_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "cloudtrail_logs_detect_stopped_ec2_instances" {
  title       = "Detect Stopped Instances"
  description = "Detect stopped instances to check for unauthorized changes."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_stopped_ec2_instances

  tags = local.cloudtrail_log_detection_common_tags
}

detection "cloudtrail_logs_detect_ec2_gateway_updates" {
  title       = "Detect EC2 Gateway Updates"
  description = "Detect EC2 gateway updates to check for changes in network configurations."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_ec2_gateway_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "cloudtrail_logs_detect_ec2_full_network_packet_capture_updates" {
  title       = "Detect EC2 Full Network Packet Capture Updates"
  description = "Detect updates to EC2 full network packet capture configurations to identify potential misuse of Traffic Mirroring, which could be exploited to exfiltrate sensitive data from unencrypted internal traffic."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_ec2_full_network_packet_capture_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

//TODO: should this be in vpc?
detection "cloudtrail_logs_detect_ec2_flow_logs_deletion_updates" {
  title       = "Detect EC2 Flow Logs Deletion Updates"
  description = "Detect EC2 flow logs deletion updates to check for unauthorized changes."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_ec2_flow_logs_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_ec2_snapshot_updates" {
  title       = "Detect EC2 Snapshot Updates"
  description = "Detect EC2 snapshot updates to check for unauthorized changes."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_ec2_snapshot_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_ec2_ami_updates" {
  title       = "Detect EC2 AMI Updates"
  description = "Detect EC2 AMI updates to check for unauthorized changes."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_ec2_ami_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0002:T1204"
  })
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
      and error_code is null
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
      and error_code is null
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
      and error_code is null
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
      and error_code is null
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
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_ec2_flow_logs_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_flow_logs_deletion_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DeleteFlowLogs'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_ec2_ami_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_ami_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('CopyFpgaImage', 'CopyImage', 'CreateFpgaImage', 'CreateImage', 'CreateRestoreImageTask', 'CreateStoreImageTask', 'ImportImage')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_stopped_ec2_instances" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_stopped_ec2_instances_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'StopInstances'
      and error_code is null
    order by
      event_time desc;
  EOQ
}