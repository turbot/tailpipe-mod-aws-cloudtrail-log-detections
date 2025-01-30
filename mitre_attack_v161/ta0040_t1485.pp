locals {
  mitre_attack_v161_ta0040_t1485_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_attack_technique_id = "T1485"
  })
}

benchmark "mitre_attack_v161_ta0040_t1485" {
  title         = "T1485 Data Destruction"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1485.md")
  children = [
    detection.ebs_volume_detached,
    detection.eventbridge_rule_deleted,
    detection.guardduty_detector_deleted,
    detection.kms_key_deletion_scheduled,
    detection.rds_db_cluster_deletion_protection_disabled,
    detection.rds_db_instance_deletion_protection_disabled,
    detection.s3_bucket_deleted,
  ]

  tags = local.mitre_attack_v161_ta0040_t1485_common_tags
}
