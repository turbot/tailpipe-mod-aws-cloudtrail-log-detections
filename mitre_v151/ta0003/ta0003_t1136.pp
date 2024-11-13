locals {
  mitre_v151_ta0003_t1136_common_tags = merge(local.mitre_v151_ta0003_common_tags, {
    mitre_technique_id = "T1136"
  })
}

detection_benchmark "mitre_v151_ta0003_t1136" {
  title         = "T1136 Create Account"
  type          = "benchmark"
  documentation = file("./mitre_v151/docs/ta0003_t1136.md")
  children = [
    detection.cloudtrail_logs_detect_iam_entity_created_without_cloudformation
  ]

  tags = local.mitre_v151_ta0003_t1136_common_tags
}
