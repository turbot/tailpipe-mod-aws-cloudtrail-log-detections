locals {
  cloudtrail_log_detection_cloudfront_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/CloudFront"
  })

  cloudtrail_logs_detect_cloudfront_distribution_updates_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
}

benchmark "cloudtrail_logs_cloudfront_detections" {
  title       = "CloudFront Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for CloudFront events."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_cloudfront_distributions_with_default_certificates_disabled,
    detection.cloudtrail_logs_detect_cloudfront_distributions_with_failover_criteria_modified,
    detection.cloudtrail_logs_detect_cloudfront_distributions_with_geo_restriction_disabled,
    detection.cloudtrail_logs_detect_cloudfront_distributions_with_logging_disabled,
    detection.cloudtrail_logs_detect_public_access_granted_to_cloudfront_distribution_origins,
  ]

  tags = merge(local.cloudtrail_log_detection_cloudfront_common_tags, {
    type    = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_cloudfront_distributions_with_default_certificates_disabled" {
  title           = "Detect CloudFront Distributions with Default Certificates Disabled"
  description     = "Detect CloudFront distributions with default certificates disabled to check for misconfigurations that could lead to insecure connections or unauthorized access, compromising data integrity and security."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_cloudfront_distributions_with_default_certificates_disabled

  tags = merge(local.cloudtrail_log_detection_cloudfront_common_tags, {
    mitre_attack_ids = "TA0005:T1562.004"
  })
}

query "cloudtrail_logs_detect_cloudfront_distributions_with_default_certificates_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudfront_distribution_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name in ('UpdateDistribution', 'CreateDistribution')
      and json_extract_string(request_parameters, '$.viewer_certificate.cloudfront_default_certificate') != 'true'
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudfront_distributions_with_geo_restriction_disabled" {
  title           = "Detect CloudFront Distributions with Geo-restriction Disabled"
  description = "Detect CloudFront distributions with geo-restriction disabled to check for misconfigurations that could allow access from restricted geographic locations, potentially exposing resources to unauthorized or malicious activity."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_cloudfront_distributions_with_geo_restriction_disabled

  tags = merge(local.cloudtrail_log_detection_cloudfront_common_tags, {
    mitre_attack_ids = "TA0005:T1562.004"
  })
}

query "cloudtrail_logs_detect_cloudfront_distributions_with_geo_restriction_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudfront_distribution_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name = 'UpdateDistribution'
      and json_extract_string(request_parameters, '$.restrictions.geo_restriction.restriction_type') != 'none'
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_public_access_granted_to_cloudfront_distribution_origins" {
  title           = "Detect Public Access Granted to CloudFront Distribution Origins"
  description     = "Detect CloudFront origins that allow public access, which can enable data exfiltration."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_public_access_granted_to_cloudfront_distribution_origins

  tags = merge(local.cloudtrail_log_detection_cloudfront_common_tags, {
    mitre_attack_ids = "TA0010:T1071"
  })
}

query "cloudtrail_logs_detect_public_access_granted_to_cloudfront_distribution_origins" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudfront_distribution_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name in ('CreateDistribution', 'UpdateDistribution')
      -- TODO: Fix this condition
      --and request_parameters.origins.items[*].s3_origin_config.origin_access_identity is null
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudfront_distributions_with_logging_disabled" {
  title           = "Detect CloudFront Distributions with Logging Disabled"
  description = "Detect CloudFront distributions with logging disabled to check for changes that could hinder monitoring and auditing, potentially obscuring malicious activity or misconfigurations."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_cloudfront_distributions_with_logging_disabled

  tags = merge(local.cloudtrail_log_detection_cloudfront_common_tags, {
    mitre_attack_ids = "TA0005:T1562.002"
  })
}

query "cloudtrail_logs_detect_cloudfront_distributions_with_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudfront_distribution_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name = 'UpdateDistribution'
      and json_extract_string(request_parameters, '$.logging.enabled') = 'false'
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudfront_distributions_with_failover_criteria_modified" {
  title           = "Detect CloudFront Distributions with Failover Criteria Modified"
  description = "Detect modifications to CloudFront distribution failover criteria to check for changes that could enable unintended data redirection or exfiltration, compromising data confidentiality and availability."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_cloudfront_distributions_with_failover_criteria_modified

  tags = merge(local.cloudtrail_log_detection_cloudfront_common_tags, {
    mitre_attack_ids = "TA0010:T1048"
  })
}

query "cloudtrail_logs_detect_cloudfront_distributions_with_failover_criteria_modified" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudfront_distribution_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudfront.amazonaws.com'
      and event_name = 'UpdateDistribution'
      and json_extract(request_parameters, '$.origins.items') is not null
      and json_array_length(json_extract(request_parameters, '$.origins.items[*].failover_criteria.status_codes')) > 0
    order by
      event_time desc;
  EOQ
}
