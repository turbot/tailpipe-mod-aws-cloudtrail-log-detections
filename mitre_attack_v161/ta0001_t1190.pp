locals {
  mitre_attack_v161_ta0001_t1190_common_tags = merge(local.mitre_attack_v161_ta0001_common_tags, {
    mitre_technique_id = "T1190"
  })
}

benchmark "mitre_attack_v161_ta0001_t1190" {
  title         = "T1190 Exploit Public-Facing Application"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0001_t1190.md")
  children = [
    detection.detect_public_access_granted_to_api_gateway_rest_apis,
    detection.lambda_function_public_access_granted,
    detection.rds_db_instance_assigned_public_ip_address,
    detection.vpc_security_group_ingress_egress_rule_updated,
    detection.s3_bucket_public_access_granted
  ]

  tags = local.mitre_attack_v161_ta0001_t1190_common_tags
}
