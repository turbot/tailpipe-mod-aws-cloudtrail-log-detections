locals {
  mitre_attack_v161_ta0005_t1070_common_tags = merge(local.mitre_attack_v161_ta0005_common_tags, {
    mitre_technique_id = "T1070"
  })
}

benchmark "mitre_attack_v161_ta0005_t1070" {
  title         = "T1070 Indicator Removal"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1070.md")
  children = [
    detection.codebuild_project_environment_variable_updated,
    detection.kms_key_deletion_scheduled,
    detection.s3_bucket_granted_public_access,
    detection.ses_identity_feedback_forwarding_disabled,
    detection.sqs_queue_dlq_disabled,
    detection.vpc_deleted,
    detection.vpc_flow_log_deleted,
    detection.vpc_peering_connection_deleted,
    detection.vpc_route_table_deleted,
    detection.vpc_route_table_association_replaced,
    detection.vpc_route_table_route_deleted,
    detection.vpc_route_table_route_disassociated,
    detection.vpc_security_group_ingress_egress_rule_authorized_to_allow_all,
  ]

  tags = local.mitre_attack_v161_ta0005_t1070_common_tags
}

