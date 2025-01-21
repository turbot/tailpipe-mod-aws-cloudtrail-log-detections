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
    detection.detect_codebuild_projects_with_environment_variable_updates,
    detection.kms_key_scheduled_deletion,
    detection.s3_bucket_public_access_granted,
    detection.ses_feedback_forwarding_disabled,
    detection.sqs_queue_dlq_disabled,
    detection.vpc_deleted,
    detection.vpc_flow_log_deleted,
    detection.vpc_peering_connection_deleted,
    detection.vpc_route_table_deleted,
    detection.vpc_route_table_association_replaced,
    detection.vpc_route_table_route_deleted,
    detection.vpc_route_table_route_disassociated,
    detection.vpc_security_group_ingress_egress_rule_authorized_to_allow_all_ipv4,
    detection.vpc_security_group_ingress_egress_rule_authorized_to_allow_all_ipv6,
  ]

  tags = local.mitre_attack_v161_ta0005_t1070_common_tags
}

