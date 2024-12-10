locals {
  mitre_v151_ta0002_t1072_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1072"
  })
}

benchmark "mitre_v151_ta0002_t1072" {
  title         = "T1072 Software Deployment Tools"
  type          = "detection"
  //documentation = file("./mitre_v151/docs/ta0002_t1072.md")
  children = [
    detection.cloudtrail_logs_detect_ecs_task_execution,
  ]

  tags = local.mitre_v151_ta0002_t1072_common_tags
}
