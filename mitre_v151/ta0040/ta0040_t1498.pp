locals {
  mitre_v151_ta0040_t1498_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1498"
  })

  cloudtrail_logs_detect_network_dos_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0040_t1498" {
  title         = "T1498 Network Denial of Service"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1498.md")
  children = [
    detection.cloudtrail_logs_detect_network_dos
  ]

  tags = local.mitre_v151_ta0040_t1498_common_tags
}

detection "cloudtrail_logs_detect_network_dos" {
  title       = "Detect Network Denial of Service"
  description = "Detect modifications to security groups that allow unrestricted inbound traffic."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_network_dos.md")
  query       = query.cloudtrail_logs_detect_network_dos

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1498"
  })
}

query "cloudtrail_logs_detect_network_dos" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_network_dos_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupIngress')
      and json_array_length(request_parameters.ipPermissions) > 10
    order by
      event_time desc;
  EOQ
}
