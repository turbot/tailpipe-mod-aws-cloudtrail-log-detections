locals {
  mitre_attack_v161_ta0003_t1525_common_tags = merge(local.mitre_attack_v161_ta0003_common_tags, {
    mitre_technique_id = "T1525"
  })
}

benchmark "mitre_attack_v161_ta0003_t1525" {
  title = "T1525 Malicious Image"
  type = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1525.md")
  children = [
    detection.detect_ec2_ami_copied_from_external_accounts,
    detection.detect_ec2_ami_imported_from_external_accounts,
    detection.detect_ec2_ami_restore_image_task_from_external_accounts,
    detection.detect_ec2_ami_store_image_tasks_from_external_accounts,
  ]

  tags = local.mitre_attack_v161_ta0003_t1525_common_tags
}