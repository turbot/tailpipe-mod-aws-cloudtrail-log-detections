locals {
  mitre_v151_ta0007_t1016_common_tags = merge(local.mitre_v151_ta0007_common_tags, {
    mitre_technique_id = "T1016"
  })

cloudtrail_logs_detect_network_configuration_discovery_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0007_t1016" {
  title         = "T1016 System Network Configuration Discovery"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0007_t1016.md")
  children = [
    detection.cloudtrail_logs_detect_network_configuration_discovery
  ]

  tags = local.mitre_v151_ta0007_t1016_common_tags
}


detection "cloudtrail_logs_detect_network_configuration_discovery" {
  title       = "Detect Network Configuration Discovery"
  description = "Detect actions querying VPCs, subnets, or route tables."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_network_configuration_discovery.md")
  query       = query.cloudtrail_logs_detect_network_configuration_discovery

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0007:T1016"
  })
}

query "cloudtrail_logs_detect_network_configuration_discovery" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_network_configuration_discovery_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in (
        'DescribeVpcs',
        'DescribeSubnets',
        'DescribeRouteTables'
      )
      and error_code is null
    order by
      event_time desc;
  EOQ
}