locals {
  mitre_v151_ta0040_t1498_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1498"
  })
}

benchmark "mitre_v151_ta0040_t1498" {
  title         = "T1498 Network Denial of Service"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0040_t1498.md")
  children = [
    detection.cloudtrail_logs_detect_ec2_security_group_ingress_egress_updates
  ]

  tags = local.mitre_v151_ta0040_t1498_common_tags
}

