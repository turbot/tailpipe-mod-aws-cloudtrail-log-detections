locals {
  mitre_v151_ta0002_t1204_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1204"
  })
}

benchmark "mitre_v151_ta0002_t1204" {
  title         = "T1204 User Execution"
  type          = "detection"
  //documentation = file("./mitre_v151/docs/ta0002_t1204.md")
  children = [
    detection.cloudtrail_logs_detect_ec2_user_data_execution
  ]

  tags = local.mitre_v151_ta0002_t1204_common_tags
}
