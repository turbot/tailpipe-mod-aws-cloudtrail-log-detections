locals {
  mitre_v151_ta0005_t1562_common_tags = merge(local.mitre_v151_ta0005_common_tags, {
    mitre_technique_id = "T1562"
  })
}

detection_benchmark "mitre_v151_ta0005_t1562" {
  title         = "T1562 Impair Defenses"
  type          = "benchmark"
  documentation = file("./mitre_v151/docs/ta0005_t1562.md")
  children = [
    detection_benchmark.mitre_v151_ta0005_t1562_001
  ]

  tags = local.mitre_v151_ta0005_t1562_common_tags
}

detection_benchmark "mitre_v151_ta0005_t1562_001" {
  title         = "T1562.001 Disable or Modify Tools"
  type          = "benchmark"
  documentation = file("./mitre_v151/docs/ta0005_t1562_001.md")
  children = [
    detection.cloudtrail_logs_detect_cloudtrail_trail_updates
  ]

  tags = merge(local.mitre_v151_ta0005_t1562_common_tags, {
    mitre_technique_id = "T1562.001"
  })
}
