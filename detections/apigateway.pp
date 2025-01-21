locals {
  apigateway_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/APIGateway"
  })

}

benchmark "apigateway_detections" {
  title       = "API Gateway Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for API Gateway events."
  type        = "detection"
  children = [
    detection.apigateway_rest_api_granted_public_access
  ]

  tags = merge(local.apigateway_common_tags, {
    type = "Benchmark"
  })
}

detection "apigateway_rest_api_granted_public_access" {
  title           = "API Gateway Rest API Granted Public Access"
  description     = "Detect when an API Gateway Rest API was created with public access to check for risks of exposing internal services, which could lead to unauthorized access and data breaches."
  documentation   = file("./detections/docs/apigateway_rest_api_granted_public_access.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.apigateway_rest_api_granted_public_access

  tags = merge(local.apigateway_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "apigateway_rest_api_granted_public_access" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_rest_api_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'apigateway.amazonaws.com'
      and event_name = 'CreateRestApi'
      and (request_parameters -> 'createRestApiInput' -> 'endpointConfiguration' ->> 'types') like '%EDGE%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}