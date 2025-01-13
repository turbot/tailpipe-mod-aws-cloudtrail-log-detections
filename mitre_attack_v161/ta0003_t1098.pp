locals {
  mitre_attack_v161_ta0003_t1098_common_tags = merge(local.mitre_attack_v161_ta0003_common_tags, {
    mitre_technique_id = "T1098"
  })
}

benchmark "mitre_attack_v161_ta0003_t1098" {
  title         = "T1098 Account Manipulation"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1098.md")
  children = [
    detection.detect_iam_users_with_console_access_enabled,
    detection.detect_rds_db_instance_master_password_updates,
    detection.detect_ec2_instances_user_data_modifications_with_ssh_key_additions,
  ]

  tags = local.mitre_attack_v161_ta0003_t1098_common_tags
}
