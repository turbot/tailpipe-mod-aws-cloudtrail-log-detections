locals {
  mitre_v151_ta0001_t1199_common_tags = merge(local.mitre_v151_ta0001_common_tags, {
    mitre_technique_id = "T1199"
  })
}

benchmark "mitre_v151_ta0001_t1199" {
  title         = "T1199 Trusted Relationship"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0001_t1199.md")
  children = [
    detection.cloudtrail_logs_detect_ec2_ami_copied_from_external_accounts,
    detection.cloudtrail_logs_detect_ec2_ami_imported_from_external_accounts,
    detection.cloudtrail_logs_detect_public_access_granted_to_api_gateways,
    detection.cloudtrail_logs_detect_public_access_granted_to_ebs_snapshots,
    detection.cloudtrail_logs_detect_public_access_granted_to_iam_roles,
    detection.cloudtrail_logs_detect_public_access_granted_to_iam_users,
    detection.cloudtrail_logs_detect_public_access_granted_to_lambda_functions,
    detection.cloudtrail_logs_detect_public_access_granted_to_rds_db_instances,
  ]

  tags = local.mitre_v151_ta0001_t1199_common_tags
}
