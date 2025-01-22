locals {
  mitre_attack_v161_ta0010_t1567_common_tags = merge(local.mitre_attack_v161_ta0010_common_tags, {
    mitre_technique_id = "T1567"
  })
}

benchmark "mitre_attack_v161_ta0010_t1567" {
  title         = "T1567 Exfiltration Over Web Service"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0010_t1567.md")
  children = [
    benchmark.mitre_attack_v161_ta0010_t1567_001
  ]

  tags = local.mitre_attack_v161_ta0010_t1567_common_tags
}

benchmark "mitre_attack_v161_ta0010_t1567_001" {
  title         = "T1567.001 Exfiltration to Code Repository"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0010_t1567_001.md")
  children = [
    detection.codebuild_project_granted_public_access,
    detection.sqs_queue_granted_public_access,
    detection.sqs_queue_created_with_encryption_at_rest_disabled,
    detection.ssm_document_shared_publicly,
    detection.sns_topic_granted_public_access,
  ]

  tags = merge(local.mitre_attack_v161_ta0010_t1567_common_tags, {
    mitre_technique_id = "T1567.001"
  })
}