locals {
  mitre_v151_ta0008_t1550_004_common_tags = merge(local.mitre_v151_ta0008_common_tags, {
    mitre_technique_id = "T1550.004"
  })

  cloudtrail_logs_detect_alternate_auth_material_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0008_t1550_004" {
  title         = "T1550.004 Use Alternate Authentication Material"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0008_t1550_004.md")
  children = [
    detection.cloudtrail_logs_detect_alternate_auth_material
  ]

  tags = local.mitre_v151_ta0008_t1550_004_common_tags
}

detection "cloudtrail_logs_detect_alternate_auth_material" {
  title       = "Detect Use of Alternate Authentication Material"
  description = "Detect use of alternate credentials like API keys or access tokens."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_alternate_auth_material.md")
  query       = query.cloudtrail_logs_detect_alternate_auth_material

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0008:T1550.004"
  })
}

query "cloudtrail_logs_detect_alternate_auth_material" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_alternate_auth_material_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'sts.amazonaws.com'
      and event_name = 'GetSessionToken'
      and user_identity.type = 'AssumedRole'
    order by
      event_time desc;
  EOQ
}
