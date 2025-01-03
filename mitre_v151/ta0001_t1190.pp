locals {
  mitre_v151_ta0001_t1190_common_tags = merge(local.mitre_v151_ta0001_common_tags, {
    mitre_technique_id = "T1190"
  })
}

benchmark "mitre_v151_ta0001_t1190" {
  title         = "T1190 Exploit Public-Facing Application"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0001_t1190.md")
  children = [
    detection.cloudtrail_logs_detect_public_access_granted_to_api_gateways,
    detection.cloudtrail_logs_detect_public_access_granted_to_lambda_functions,
    detection.cloudtrail_logs_detect_public_access_granted_to_rds_db_instances,
    detection.cloudtrail_logs_detect_public_access_granted_to_waf_rules,
    detection.cloudtrail_logs_detect_vpc_security_group_ingress_egress_updates,
    detection.cloudtrail_logs_detect_public_access_granted_to_s3_buckets
  ]

  tags = local.mitre_v151_ta0001_t1190_common_tags
}
