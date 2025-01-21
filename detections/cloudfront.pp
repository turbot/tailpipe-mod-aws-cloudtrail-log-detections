locals {
  cloudfront_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/CloudFront"
  })

}

benchmark "cloudfront_detections" {
  title       = "CloudFront Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for CloudFront events."
  type        = "detection"
  children = [
    detection.cloudfront_distribution_default_certificate_disabled,
    detection.cloudfront_distribution_failover_criteria_modified,
    detection.cloudfront_distribution_geo_restriction_disabled,
    detection.cloudfront_distribution_logging_disabled,
    detection.cloudfront_distribution_origin_granted_public_access,
  ]

  tags = merge(local.cloudfront_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudfront_distribution_default_certificate_disabled" {
  title           = "CloudFront Distribution Default Certificate Disabled"
  description     = "Detect when a CloudFront distribution's default certificate was disabled to check for misconfigurations that could lead to insecure connections or unauthorized access, compromising data integrity and security."
  documentation   = file("./detections/docs/cloudfront_distribution_default_certificate_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudfront_distribution_default_certificate_disabled

  tags = merge(local.cloudfront_common_tags, {
    mitre_attack_ids = "TA0005:T1562.004"
  })
}

query "cloudfront_distribution_default_certificate_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name in ('UpdateDistribution', 'CreateDistribution')
      and (request_parameters -> 'viewer_certificate' -> 'cloudfront_default_certificate') = false
    order by
      event_time desc;
  EOQ
}

detection "cloudfront_distribution_geo_restriction_disabled" {
  title           = "CloudFront Distribution Geo-restriction Disabled"
  description     = "Detect when a CloudFront distribution had geo-restriction disabled to check for misconfigurations that could allow access from restricted geographic locations, potentially exposing resources to unauthorized or malicious activity."
  documentation   = file("./detections/docs/cloudfront_distribution_geo_restriction_disabled.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.cloudfront_distribution_geo_restriction_disabled

  tags = merge(local.cloudfront_common_tags, {
    mitre_attack_ids = "TA0005:T1562.004"
  })
}

query "cloudfront_distribution_geo_restriction_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name = 'UpdateDistribution'
      and (request_parameters -> 'restrictions' -> 'geo_restriction' ->> 'restriction_type') != 'none'
    order by
      event_time desc;
  EOQ
}

detection "cloudfront_distribution_origin_granted_public_access" {
  title           = "CloudFront Distribution Origin Granted Public Access"
  description     = "Detect when a CloudFront distribution origin was granted public access to check for risks of data exfiltration or unauthorized access."
  documentation   = file("./detections/docs/cloudfront_distribution_origin_granted_public_access.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.cloudfront_distribution_origin_granted_public_access

  tags = merge(local.cloudfront_common_tags, {
    mitre_attack_ids = "TA0010:T1071"
  })
}

query "cloudfront_distribution_origin_granted_public_access" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name in ('CreateDistribution', 'UpdateDistribution')
      and (request_parameters -> 'origins' -> 'items') is not null
      and json_array_length(request_parameters -> 'origins' -> 'items') > 0
      and (
        json_array_length(
          (request_parameters -> 'origins' -> 'items') -> 's3_origin_config' -> 'origin_access_identity'
        ) = 0
      )
    order by
      event_time desc;
  EOQ
}

detection "cloudfront_distribution_logging_disabled" {
  title           = "CloudFront Distribution Logging Disabled"
  description     = "Detect when a CloudFront distribution's logging was disabled to check for changes that could hinder monitoring and auditing, potentially obscuring malicious activity or misconfigurations."
  documentation   = file("./detections/docs/cloudfront_distribution_logging_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudfront_distribution_logging_disabled

  tags = merge(local.cloudfront_common_tags, {
    mitre_attack_ids = "TA0005:T1562.002"
  })
}

query "cloudfront_distribution_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name = 'UpdateDistribution'
      and (request_parameters -> 'logging' ->> 'enabled') = 'false'
    order by
      event_time desc;
  EOQ
}

detection "cloudfront_distribution_failover_criteria_modified" {
  title           = "CloudFront Distribution Failover Criteria Modified"
  description     = "Detect when a CloudFront distribution's failover criteria was modified to check for changes that could impact the availability of resources, potentially leading to service disruptions or downtime."
  documentation   = file("./detections/docs/cloudfront_distribution_failover_criteria_modified.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudfront_distribution_failover_criteria_modified

  tags = merge(local.cloudfront_common_tags, {
    mitre_attack_ids = "TA0010:T1048"
  })
}

query "cloudfront_distribution_failover_criteria_modified" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name = 'UpdateDistribution'
      and (request_parameters -> 'origins' -> 'items') is not null
      and json_array_length(
        (request_parameters -> 'origins' -> 'items') -> 'failover_criteria' -> 'status_codes'
      ) > 0
    order by
      event_time desc;
  EOQ
}
