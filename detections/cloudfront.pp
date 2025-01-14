locals {
  cloudfront_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/CloudFront"
  })

  detect_cloudfront_distribution_updates_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
}

benchmark "cloudfront_detections" {
  title       = "CloudFront Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for CloudFront events."
  type        = "detection"
  children    = [
    detection.detect_cloudfront_distributions_with_default_certificates_disabled,
    detection.detect_cloudfront_distributions_with_failover_criteria_modified,
    detection.detect_cloudfront_distributions_with_geo_restriction_disabled,
    detection.detect_cloudfront_distributions_with_logging_disabled,
    detection.detect_public_access_granted_to_cloudfront_distribution_origins,
  ]

  tags = merge(local.cloudfront_common_tags, {
    type    = "Benchmark"
  })
}

detection "detect_cloudfront_distributions_with_default_certificates_disabled" {
  title           = "Detect CloudFront Distributions with Default Certificates Disabled"
  description     = "Detect CloudFront distributions with default certificates disabled to check for misconfigurations that could lead to insecure connections or unauthorized access, compromising data integrity and security."
  documentation   = file("./detections/docs/detect_cloudfront_distributions_with_default_certificates_disabled.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudfront_distributions_with_default_certificates_disabled

  tags = merge(local.cloudfront_common_tags, {
    mitre_attack_ids = "TA0005:T1562.004"
  })
}

query "detect_cloudfront_distributions_with_default_certificates_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_cloudfront_distribution_updates_sql_columns}
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

detection "detect_cloudfront_distributions_with_geo_restriction_disabled" {
  title           = "Detect CloudFront Distributions with Geo-restriction Disabled"
  description     = "Detect CloudFront distributions with geo-restriction disabled to check for misconfigurations that could allow access from restricted geographic locations, potentially exposing resources to unauthorized or malicious activity."
  documentation   = file("./detections/docs/detect_cloudfront_distributions_with_geo_restriction_disabled.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudfront_distributions_with_geo_restriction_disabled

  tags = merge(local.cloudfront_common_tags, {
    mitre_attack_ids = "TA0005:T1562.004"
  })
}

query "detect_cloudfront_distributions_with_geo_restriction_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_cloudfront_distribution_updates_sql_columns}
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

detection "detect_public_access_granted_to_cloudfront_distribution_origins" {
  title           = "Detect Public Access Granted to CloudFront Distribution Origins"
  description     = "Detect CloudFront origins that allow public access, which can enable data exfiltration."
  documentation   = file("./detections/docs/detect_public_access_granted_to_cloudfront_distribution_origins.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_public_access_granted_to_cloudfront_distribution_origins

  tags = merge(local.cloudfront_common_tags, {
    mitre_attack_ids = "TA0010:T1071"
  })
}

query "detect_public_access_granted_to_cloudfront_distribution_origins" {
  sql = <<-EOQ
    select
      ${local.detect_cloudfront_distribution_updates_sql_columns}
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

detection "detect_cloudfront_distributions_with_logging_disabled" {
  title           = "Detect CloudFront Distributions with Logging Disabled"
  description     = "Detect CloudFront distributions with logging disabled to check for changes that could hinder monitoring and auditing, potentially obscuring malicious activity or misconfigurations."
  documentation   = file("./detections/docs/detect_cloudfront_distributions_with_logging_disabled.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudfront_distributions_with_logging_disabled

  tags = merge(local.cloudfront_common_tags, {
    mitre_attack_ids = "TA0005:T1562.002"
  })
}

query "detect_cloudfront_distributions_with_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_cloudfront_distribution_updates_sql_columns}
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

detection "detect_cloudfront_distributions_with_failover_criteria_modified" {
  title           = "Detect CloudFront Distributions with Failover Criteria Modified"
  description = "Detect modifications to CloudFront distribution failover criteria to check for changes that could enable unintended data redirection or exfiltration, compromising data confidentiality and availability."
  documentation   = file("./detections/docs/detect_cloudfront_distributions_with_failover_criteria_modified.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudfront_distributions_with_failover_criteria_modified

  tags = merge(local.cloudfront_common_tags, {
    mitre_attack_ids = "TA0010:T1048"
  })
}

query "detect_cloudfront_distributions_with_failover_criteria_modified" {
  sql = <<-EOQ
    select
      ${local.detect_cloudfront_distribution_updates_sql_columns}
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
