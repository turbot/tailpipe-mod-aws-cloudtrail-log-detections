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
    detection.lambda_function_granted_public_access,
    detection.lambda_function_environment_variable_updated_with_encryption_at_rest_disabled,
    detection.lambda_function_created_with_function_code_encryption_at_rest_disabled,
  ]

  tags = local.mitre_attack_v161_ta0003_t1546_common_tags
}