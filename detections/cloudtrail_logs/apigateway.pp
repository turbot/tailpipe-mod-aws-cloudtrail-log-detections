locals {
  cloudtrail_logs_detect_public_access_granted_to_api_gateways_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.createRestApiInput.name")
}

benchmark "cloudtrail_logs_apigateway_detections" {
  title       = "API Gateway Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's API Gateway logs."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_public_access_granted_to_api_gateways
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/APIGateway"
  })
}

detection "cloudtrail_logs_detect_public_access_granted_to_api_gateways" {
  title       = "Detect Public Access Granted to API Gateways"
  description = "Detect when an API Gateway is created with public access, potentially exposing internal services."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_public_access_granted_to_api_gateways

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "cloudtrail_logs_detect_public_access_granted_to_api_gateways" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_public_access_granted_to_api_gateways_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'apigateway.amazonaws.com'
      and event_name = 'CreateRestApi'
      and json_extract(request_parameters, '$.createRestApiInput.endpointConfiguration.types') like '%EDGE%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}