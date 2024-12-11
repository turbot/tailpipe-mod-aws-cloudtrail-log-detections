locals {
  mitre_v151_ta0040_t1484_002_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1484.002"
  })

  cloudtrail_logs_detect_group_policy_modification_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0040_t1484_002" {
  title         = "T1484.002 Group Policy Modification"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1484_002.md")
  children = [
    detection.cloudtrail_logs_detect_group_policy_modification
  ]

  tags = local.mitre_v151_ta0040_t1484_002_common_tags
}

detection "cloudtrail_logs_detect_group_policy_modification" {
  title       = "Detect Group Policy Modifications"
  description = "Detect unauthorized modifications to IAM group policies."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_group_policy_modification.md")
  query       = query.cloudtrail_logs_detect_group_policy_modification

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1484.002"
  })
}

query "cloudtrail_logs_detect_group_policy_modification" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_group_policy_modification_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name in ('PutGroupPolicy', 'AttachGroupPolicy')
      and error_code is null
    order by
      event_time desc;
  EOQ
}
