locals {
  apigateway_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/APIGateway"
  })

  detect_public_access_granted_to_api_gateways_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.createRestApiInput.name')")
}

benchmark "apigateway_detections" {
  title       = "API Gateway Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for API Gateway events."
  type        = "detection"
  children    = [
    detection.detect_public_access_granted_to_api_gateways
  ]

  tags = merge(local.apigateway_common_tags, {
    type    = "Benchmark"
  })
}

detection "detect_public_access_granted_to_api_gateways" {
  title       = "Detect Public Access Granted to API Gateways"
  description = "Detect when an API Gateway is created with public access, potentially exposing internal services."
  documentation   = file("./detections/docs/detect_public_access_granted_to_api_gateways.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_public_access_granted_to_api_gateways

  tags = merge(local.apigateway_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "detect_public_access_granted_to_api_gateways" {
  sql = <<-EOQ
    select
      ${local.detect_public_access_granted_to_api_gateways_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'apigateway.amazonaws.com'
      and event_name = 'CreateRestApi'
      and json_extract_string(request_parameters, '$.createRestApiInput.endpointConfiguration.types') like '%EDGE%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
