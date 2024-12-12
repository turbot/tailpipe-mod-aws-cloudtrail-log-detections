locals {
  mitre_v151_ta0010_t1029_common_tags = merge(local.mitre_v151_ta0010_common_tags, {
    mitre_technique_id = "T1029"
  })
}

benchmark "mitre_v151_ta0010_t1029" {
  title         = "T1029 Data Compressed Before Exfiltration"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0010_t1029.md")
  children = [
    detection.cloudtrail_logs_detect_s3_object_compressed_uploads
  ]

  tags = local.mitre_v151_ta0010_t1029_common_tags
}

