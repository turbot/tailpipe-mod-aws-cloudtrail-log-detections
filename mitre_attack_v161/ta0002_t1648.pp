locals {
  mitre_attack_v161_ta0002_t1648_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_attack_technique_id = "T1648"
  })
}

benchmark "mitre_attack_v161_ta0002_t1648" {
  title         = "T1648 Serverless Execution"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0002_t1648.md")
  children = [
    detection.lambda_function_created_with_function_code_encryption_at_rest_disabled,
    detection.lambda_function_granted_public_access,
  ]

  tags = local.mitre_attack_v161_ta0002_t1648_common_tags
}
