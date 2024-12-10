locals {
  mitre_v151_ta0002_t1059_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1059"
  })
}

benchmark "mitre_v151_ta0002_t1059" {
  title         = "T1059 Command and Scripting Interpreter"
  type          = "detection"
  //documentation = file("./mitre_v151/docs/ta0002_t1059.md")
  children = [
    detection.cloudtrail_logs_detect_lambda_invocation,
    detection.cloudtrail_logs_detect_step_function_execution,
    detection.cloudtrail_logs_detect_ssm_run_command
  ]

  tags = local.mitre_v151_ta0002_t1059_common_tags
}
