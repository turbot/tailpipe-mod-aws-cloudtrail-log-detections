locals {
  mitre_v151_ta0040_t1496_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1496"
  })

  cloudtrail_logs_detect_resource_hijacking_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0040_t1496" {
  title         = "T1496 Resource Hijacking"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1496.md")
  children = [
    detection.cloudtrail_logs_detect_resource_hijacking
  ]

  tags = local.mitre_v151_ta0040_t1496_common_tags
}

detection "cloudtrail_logs_detect_resource_hijacking" {
  title       = "Detect Resource Hijacking in EC2"
  description = "Detect unauthorized resource usage such as creating high-cost EC2 instances."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_resource_hijacking.md")
  query       = query.cloudtrail_logs_detect_resource_hijacking

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1496"
  })
}

query "cloudtrail_logs_detect_resource_hijacking" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_resource_hijacking_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('RunInstances', 'StartInstances')
      and request_parameters->>'instanceType' like 'g4%' -- Example: GPU instances
    order by
      event_time desc;
  EOQ
}
