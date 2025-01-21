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
    detection.detect_vpc_deletions,
    detection.detect_vpc_flow_log_deletions,
    detection.detect_vpc_peering_connection_deletions,
    detection.detect_vpc_route_table_deletions,
    detection.detect_vpc_route_table_replace_associations,
    detection.detect_vpc_route_tables_with_route_deletions,
    detection.detect_vpc_route_tables_with_route_disassociations,
    detection.detect_vpc_security_group_ipv4_allow_all,
    detection.detect_vpc_security_group_ipv6_allow_all,
  ]

  tags = local.mitre_attack_v161_ta0005_t1070_common_tags
}

