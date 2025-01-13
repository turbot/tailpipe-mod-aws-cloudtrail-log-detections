locals {
  mitre_attack_v161_ta0040_t1484_002_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_technique_id = "T1484.002"
  })
}

benchmark "mitre_attack_v161_ta0040_t1484_002" {
  title         = "T1484.002 Group Policy Modification"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1484_002.md")
  children = [
    detection.detect_admin_access_granted_to_iam_groups,
    detection.detect_public_access_granted_to_iam_groups,
  ]

  tags = local.mitre_attack_v161_ta0040_t1484_002_common_tags
}
