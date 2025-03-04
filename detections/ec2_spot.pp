locals {
  ec2_spot_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    folder  = "EC2"
    service = "AWS/EC2"
  })
}

detection "ec2_spot_instance_interrupted" {
  title           = "EC2 Spot Instance Interrupted"
  description     = "Detect when EC2 spot instances are interrupted. Spot instance interruptions can disrupt workloads if not properly handled, potentially causing service outages or data loss if applications aren't designed for graceful termination."
  documentation   = file("./detections/docs/ec2_spot_instance_interrupted.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.ec2_spot_instance_interrupted

  tags = merge(local.ec2_spot_common_tags, {
    mitre_attack_ids = "TA0040:T1496"
  })
}

query "ec2_spot_instance_interrupted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_instance_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and (
        event_name = 'CancelSpotInstanceRequests'
        or (
          event_name = 'TerminateInstances' 
          and json_contains(request_parameters, 'spotInstanceRequestId')
        )
      )
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ

  tags = local.ec2_spot_common_tags
}
