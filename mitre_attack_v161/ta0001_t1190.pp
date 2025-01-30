locals {
  mitre_attack_v161_ta0001_t1190_common_tags = merge(local.mitre_attack_v161_ta0001_common_tags, {
    mitre_attack_technique_id = "T1190"
  })
}

benchmark "mitre_attack_v161_ta0001_t1190" {
  title         = "T1190 Exploit Public-Facing Application"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0001_t1190.md")
  children = [
    detection.lambda_function_granted_public_access,
    detection.rds_db_instance_assigned_public_ip_address,
    detection.s3_bucket_policy_granted_public_access,
    detection.sns_topic_granted_public_access,
    detection.sqs_queue_granted_public_access,
    detection.ssm_document_shared_publicly,
    detection.vpc_security_group_ingress_egress_rule_updated,
  ]

  tags = local.mitre_attack_v161_ta0001_t1190_common_tags
}
