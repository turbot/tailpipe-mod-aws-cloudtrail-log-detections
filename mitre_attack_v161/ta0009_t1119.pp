locals {
  mitre_attack_v161_ta0009_t1119_common_tags = merge(local.mitre_attack_v161_ta0009_common_tags, {
    mitre_attack_technique_id = "T1119"
  })
}

benchmark "mitre_attack_v161_ta0009_t1119" {
  title         = "T1119 Automated Collection"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0009_t1119.md")
  children = [
    detection.cloudwatch_log_group_created_with_encryption_disabled,
    detection.ebs_encryption_by_default_disabled,
    detection.ebs_snapshot_created_with_encryption_disabled,
    detection.rds_db_instance_restored_from_public_snapshot,
    detection.vpc_network_acl_entry_updated_with_allow_public_access,
  ]

  tags = local.mitre_attack_v161_ta0009_t1119_common_tags
}
