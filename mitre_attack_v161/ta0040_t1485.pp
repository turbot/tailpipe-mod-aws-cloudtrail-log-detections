locals {
  mitre_attack_v161_ta0040_t1485_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_technique_id = "T1485"
  })
}

benchmark "mitre_attack_v161_ta0040_t1485" {
  title         = "T1485 Data Destruction"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1485.md")
  children = [
    detection.detect_s3_bucket_deletions,
    detection.detect_eventbridge_rule_deletions,
    detection.detect_guardduty_detector_deletions,
    detection.detect_rds_db_clusters_with_deletion_protection_disabled,
    detection.detect_rds_db_instances_with_deletion_protection_disabled,
  ]

  tags = local.mitre_attack_v161_ta0040_t1485_common_tags
}
