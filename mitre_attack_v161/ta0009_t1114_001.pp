locals {
  mitre_attack_v161_ta0009_t1114_001_common_tags = merge(local.mitre_attack_v161_ta0009_common_tags, {
    mitre_technique_id = "T1114.001"
  })
}

benchmark "mitre_attack_v161_ta0009_t1114_001" {
  title         = "T1114.001 Email Collection via AWS SES"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0009_t1114_001.md")
  children = [
    detection.detect_ses_unauthorized_email_collections
  ]

  tags = local.mitre_attack_v161_ta0009_t1114_001_common_tags
}

