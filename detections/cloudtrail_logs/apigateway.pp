locals {
  cloudtrail_logs_detect_api_gateway_public_access_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.createRestApiInput.name")
}

benchmark "cloudtrail_logs_apigateway_detections" {
  title       = "CloudTrail Log API Gateway Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's API Gateway logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_api_gateway_public_access
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/APIGateway"
  })
}

detection "cloudtrail_logs_detect_api_gateway_public_access" {
  title       = "Detect API Gateway Created with Public Access"
  description = "Detect when an API Gateway is created with public access, potentially exposing internal services."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_api_gateway_public_access

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "cloudtrail_logs_detect_api_gateway_public_access" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_api_gateway_public_access_sql_columns}
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