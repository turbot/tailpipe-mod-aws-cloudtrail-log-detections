locals {
  mitre_v161_ta0002_t1059_common_tags = merge(local.mitre_v161_ta0002_common_tags, {
    mitre_technique_id = "T1059"
  })
}

benchmark "mitre_v161_ta0002_t1059" {
  title         = "T1059 Command and Scripting Interpreter"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0002_t1059.md")
  children = [
    benchmark.mitre_v161_ta0002_t1059_t1059_009,
  ]

  tags = local.mitre_v161_ta0002_t1059_common_tags
}


benchmark "mitre_v161_ta0002_t1059_t1059_009" {
  title         = "T1059.009 Cloud API"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0002_t1059_009.md")
  children = [
    detection.cloudtrail_logs_detect_vpc_security_group_deletions,
    detection.cloudtrail_logs_detect_vpc_deletions,
    detection.cloudtrail_logs_detect_vpc_flow_log_deletions,
    detection.cloudtrail_logs_detect_cloudtrail_trails_with_logging_stopped,
  ]

  tags = local.mitre_v161_ta0002_t1059_common_tags
}