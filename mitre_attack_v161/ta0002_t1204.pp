locals {
  mitre_attack_v161_ta0002_t1204_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_technique_id = "T1204"
  })
}

benchmark "mitre_attack_v161_ta0002_t1204" {
  title         = "T1204 User Execution"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0002_t1204.md")
  children = [
    benchmark.mitre_attack_v161_ta0002_t1204_003,
  ]

  tags = local.mitre_attack_v161_ta0002_t1204_common_tags
}


benchmark "mitre_attack_v161_ta0002_t1204_003" {
  title = "T1204.003 Malicious Image"
  type = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0002_t1204_003.md")
  children = [
    detection.detect_ec2_ami_copied_from_external_accounts,
    detection.detect_ec2_ami_imported_from_external_accounts,
    detection.detect_ec2_ami_restore_image_task_from_external_accounts,
    detection.detect_ec2_ami_store_image_tasks_from_external_accounts,
  ]

  tags = local.mitre_attack_v161_ta0002_t1204_common_tags
}