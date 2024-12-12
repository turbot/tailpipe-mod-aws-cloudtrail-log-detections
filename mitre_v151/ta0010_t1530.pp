locals {
  mitre_v151_ta0010_t1530_common_tags = merge(local.mitre_v151_ta0010_common_tags, {
    mitre_technique_id = "T1530"
  })
}

benchmark "mitre_v151_ta0010_t1530" {
  title         = "T1530 Data Transfer Size Limits"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0010_t1530.md")
  children = [
    detection.cloudtrail_logs_detect_s3_large_file_downloads
  ]

  tags = local.mitre_v151_ta0010_t1530_common_tags
}
