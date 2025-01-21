locals {
  mitre_attack_v161_ta0002_t1059_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_technique_id = "T1059"
  })
}

benchmark "mitre_attack_v161_ta0002_t1059" {
  title         = "T1059 Command and Scripting Interpreter"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0002_t1059.md")
  children = [
    benchmark.mitre_attack_v161_ta0002_t1059_009,
  ]

  tags = local.mitre_attack_v161_ta0002_t1059_common_tags
}


benchmark "mitre_attack_v161_ta0002_t1059_009" {
  title         = "T1059.009 Command and Scripting Interpreter: Cloud API"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0002_t1059_009.md")
  children = [
    detection.vpc_security_group_deleted,
    detection.vpc_deleted,
    detection.vpc_flow_log_deleted,
    detection.detect_cloudtrail_trails_with_logging_stopped,
  ]

  tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_technique_id = "T1059.009"
  })
}