locals {
  mitre_v151_ta0001_t1078_common_tags = merge(local.mitre_v151_ta0001_common_tags, {
    mitre_technique_id = "T1078"
  })
}

benchmark "mitre_v151_ta0001_t1078" {
  title         = "T1078 Valid Accounts"
  //documentation = file("./cis_v130/docs/cis_v130_3.md")
  children = [
    control.cloudtrail_log_console_root_login
  ]

  tags = local.mitre_v151_ta0001_t1078_common_tags
}
