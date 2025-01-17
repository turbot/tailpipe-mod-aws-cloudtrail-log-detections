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
    detection.apigateway_rest_apis_public_access_granted,
    detection.detect_public_access_granted_to_lambda_functions,
    detection.detect_public_access_granted_to_rds_db_instances,
    detection.detect_public_access_granted_to_waf_rules,
    detection.detect_vpc_security_group_ingress_egress_updates,
    detection.detect_public_access_granted_to_s3_buckets
  ]

  tags = local.mitre_attack_v161_ta0001_t1190_common_tags
}
