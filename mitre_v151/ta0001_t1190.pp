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
    detection.cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates
  ]

  tags = local.mitre_v151_ta0001_t1190_common_tags
}
