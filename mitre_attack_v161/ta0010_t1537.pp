locals {
  mitre_attack_v161_ta0010_t1537_common_tags = merge(local.mitre_attack_v161_ta0010_common_tags, {
    mitre_attack_technique_id = "t1537"
  })
}

benchmark "mitre_attack_v161_ta0010_t1537" {
  title         = "T1537 Transfer Data to Cloud Account"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0010_t1537.md")
  children = [
    detection.ebs_snapshot_unlocked,
  ]

  tags = local.mitre_attack_v161_ta0010_t1537_common_tags
}
