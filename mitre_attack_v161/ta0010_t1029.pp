locals {
  mitre_attack_v161_ta0010_t1029_common_tags = merge(local.mitre_attack_v161_ta0010_common_tags, {
    mitre_technique_id = "T1029"
  })
}

benchmark "mitre_attack_v161_ta0010_t1029" {
  title         = "T1029 Scheduled Transfer"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0010_t1029.md")
  children = [
    detection.s3_object_compressed_uploaded
  ]

  tags = local.mitre_attack_v161_ta0010_t1029_common_tags
}

