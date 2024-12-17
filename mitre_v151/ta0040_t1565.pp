locals {
  mitre_v151_ta0040_t1565_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1565"
  })
}

benchmark "mitre_v151_ta0040_t1565" {
  title         = "T1565 Data Manipulation"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0040_t1565.md")
  children = [
    benchmark.mitre_v151_ta0040_t1565_003
  ]

  tags = local.mitre_v151_ta0040_t1565_common_tags
}

benchmark "mitre_v151_ta0040_t1565_003" {
  title         = "T1565.003 Runtime Data Manipulation"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0040_t1565_003.md")
  children = [
    detection.cloudtrail_logs_detect_waf_web_acl_disassociations
  ]

  tags = local.mitre_v151_ta0040_t1565_common_tags
}
