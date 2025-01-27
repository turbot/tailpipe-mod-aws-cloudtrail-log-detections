locals {
  ec2_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/EC2"
  })
}

benchmark "ec2_detections" {
  title       = "EC2 Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for EC2 events."
  type        = "detection"
  children = [
    detection.ec2_ami_launch_permission_updated,
    detection.ec2_instance_launched_with_public_ip,
    detection.ec2_reserved_instance_purchased,
    detection.ec2_key_pair_deleted,
  ]

  tags = merge(local.ec2_common_tags, {
    type = "Benchmark"
  })
}

detection "ec2_ami_launch_permission_updated" {
  title           = "EC2 AMI Launch Permission Updated"
  description     = "Detect when an EC2 AMI launch permission was updated. Modifying a launch permission may have allowed unauthorized access or privilege escalation, potentially exposing a sensitive resource."
  documentation   = file("./detections/docs/ec2_ami_launch_permission_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.ec2_ami_launch_permission_updated

  tags = merge(local.ec2_common_tags, {
    mitre_attack_ids = "TA0005:T1078"
  })
}

query "ec2_ami_launch_permission_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_image_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'ModifyImageAttribute'
      and (request_parameters ->> 'attributeType') = 'launchPermission'
      and (request_parameters -> 'launchPermission' -> 'add' -> 0 ->> 'group') = 'all'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "ec2_instance_launched_with_public_ip" {
  title           = "EC2 Instance Launched with Public IP Address"
  description     = "Detect when an EC2 instance was launched with a public IP address. Launching instances with public IP addresses may expose them to the internet, potentially leading to unauthorized access or attacks."
  documentation   = file("./detections/docs/ec2_instance_launched_with_public_ip.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.ec2_instance_launched_with_public_ip

  tags = merge(local.ec2_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "ec2_instance_launched_with_public_ip" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_response_elements_instance_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'RunInstances'
      and json_contains(
        (request_parameters -> 'networkInterfaces' -> 'items'),
        '{"associatePublicIpAddress": true}'
      )
      ${local.detection_sql_where_conditions}
    order by
      tp_timestamp desc;
  EOQ
}

detection "ec2_reserved_instance_purchased" {
  title           = "EC2 Reserved Instance Purchased"
  description     = "Detect when an EC2 Reserved Instance was purchased. Purchasing reserved instances may indicate changes in resource planning or cost management strategies, which should be reviewed for compliance and alignment with organizational policies."
  documentation   = file("./detections/docs/ec2_reserved_instance_purchased.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.ec2_reserved_instance_purchased

  tags = merge(local.ec2_common_tags, {
    mitre_attack_ids = "TA0040:T1587"
  })
}

query "ec2_reserved_instance_purchased" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_response_elements_reserved_instances_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'PurchaseReservedInstancesOffering'
      ${local.detection_sql_where_conditions}
    order by
      tp_timestamp desc;
  EOQ
}

detection "ec2_key_pair_deleted" {
  title           = "EC2 Key Pair Deleted"
  description     = "Detect when an EC2 key pair was deleted. Deleting key pairs may remove access to instances configured to use the key, potentially leading to disruption or unauthorized access attempts."
  documentation   = file("./detections/docs/ec2_key_pair_deleted.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.ec2_key_pair_deleted

  tags = merge(local.ec2_common_tags, {
    mitre_attack_ids = "TA0001:T1558"
  })
}

query "ec2_key_pair_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_key_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'DeleteKeyPair'
      ${local.detection_sql_where_conditions}
    order by
      tp_timestamp desc;
  EOQ
}

