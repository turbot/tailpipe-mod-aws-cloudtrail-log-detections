locals {
  mitre_attack_v161_ta0001_t1199_common_tags = merge(local.mitre_attack_v161_ta0001_common_tags, {
    mitre_attack_technique_id = "T1199"
  })
}

benchmark "mitre_attack_v161_ta0001_t1199" {
  title = "T1199 Trusted Relationship"
  type  = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0001_t1199.md")
  children = [
    detection.lambda_function_granted_public_access,
    detection.rds_db_instance_assigned_public_ip_address,
  ]

  tags = local.mitre_attack_v161_ta0001_t1199_common_tags
}
