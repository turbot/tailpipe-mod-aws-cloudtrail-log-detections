locals {
  mitre_attack_v161_ta0001_t1199_common_tags = merge(local.mitre_attack_v161_ta0001_common_tags, {
    mitre_technique_id = "T1199"
  })
}

benchmark "mitre_attack_v161_ta0001_t1199" {
  title         = "T1199 Trusted Relationship"
  type          = "detection"
  # documentation = file("./mitre_attack_v161/docs/ta0001_t1199.md")
  children = [
    detection.detect_ec2_ami_copied_from_external_accounts,
    detection.detect_ec2_ami_imported_from_external_accounts,
    detection.detect_public_access_granted_to_api_gateway_rest_apis,
    detection.ebs_snapshot_shared_publicly,
    detection.detect_public_access_granted_to_iam_roles,
    detection.detect_public_access_granted_to_iam_users,
    detection.detect_public_access_granted_to_lambda_functions,
    detection.detect_public_access_granted_to_rds_db_instances,
  ]

  tags = local.mitre_attack_v161_ta0001_t1199_common_tags
}
