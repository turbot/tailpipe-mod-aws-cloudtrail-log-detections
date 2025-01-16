locals {
  mitre_attack_v161_ta0003_t1546_common_tags = merge(local.mitre_attack_v161_ta0003_common_tags, {
    mitre_technique_id = "T1546"
  })
}


benchmark "mitre_attack_v161_ta0003_t1546" {
  title = "T1546 Event Triggered Execution"
  type = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1546.md")
  children = [
    detection.detect_public_access_granted_to_lambda_functions,
    detection.detect_lambda_function_code_updates_without_publish,
    detection.detect_lambda_functions_with_unencrypted_environment_variables,
    detection.detect_lambda_functions_with_unencrypted_code,
  ]

  tags = local.mitre_attack_v161_ta0003_t1546_common_tags
}