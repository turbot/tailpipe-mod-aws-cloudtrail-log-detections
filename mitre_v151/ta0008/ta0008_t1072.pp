locals {
  mitre_v151_ta0008_t1072_common_tags = merge(local.mitre_v151_ta0008_common_tags, {
    mitre_technique_id = "T1072"
  })

  cloudtrail_logs_detect_software_deployment_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0008_t1072" {
  title         = "T1072 Software Deployment Tools"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0008_t1072.md")
  children = [
    detection.cloudtrail_logs_detect_software_deployment
  ]

  tags = local.mitre_v151_ta0008_t1072_common_tags
}

detection "cloudtrail_logs_detect_software_deployment" {
  title       = "Detect Software Deployment Tools Usage"
  description = "Detect unauthorized use of software deployment tools for lateral movement."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_software_deployment.md")
  query       = query.cloudtrail_logs_detect_software_deployment

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0008:T1072"
  })
}

query "cloudtrail_logs_detect_software_deployment" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_software_deployment_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'codedeploy.amazonaws.com'
      and event_name = 'CreateDeployment'
      and error_code is null
    order by
      event_time desc;
  EOQ
}
