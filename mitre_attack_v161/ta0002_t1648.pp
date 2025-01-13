locals {
  mitre_attack_v161_ta0002_t1648_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_technique_id = "T1648"
  })
}

benchmark "mitre_attack_v161_ta0002_t1648" {
  title         = "T1648 Serverless Execution"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0002_t1648.md")
  children = [
    detection.detect_public_access_granted_to_lambda_functions,
    detection.detect_lambda_function_code_updates_without_publish,
    detection.detect_lambda_functions_with_unencrypted_environment_variables,
    detection.detect_lambda_functions_with_unencrypted_code,
  ]

  tags = local.mitre_attack_v161_ta0002_t1648_common_tags
}
