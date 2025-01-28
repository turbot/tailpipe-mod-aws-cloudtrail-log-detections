locals {
  mitre_attack_v161_ta0009_t1530_common_tags = merge(local.mitre_attack_v161_ta0009_common_tags, {
    mitre_attack_technique_id = "T1530"
  })
}

benchmark "mitre_attack_v161_ta0009_t1530" {
  title         = "T1530 Data from Cloud Storage"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0009_t1530.md")
  children = [
    detection.s3_large_file_downloaded
  ]

  tags = local.mitre_attack_v161_ta0009_t1530_common_tags
}
