// TODO: Add author to all detections
// TODO: Detection vs check naming?

locals {
  cloudtrail_log_common_tags = merge(local.aws_common_tags, {
    service = "AWS/CloudTrail"
  })

  # Store the replace logic in a local variable
  aws_cloudtrail_trail_update_detection_sql = replace(local.common_dimensions_cloudtrail_log_sql, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'name'")
  aws_ec2_security_group_ingress_egress_update_detection_sql = replace(local.common_dimensions_cloudtrail_log_sql, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'groupId'")
  aws_iam_root_console_login_detection_sql = replace(local.common_dimensions_cloudtrail_log_sql, "__RESOURCE_SQL__", "''")
}

detection_benchmark "cloudtrail_log_checks" {
  title       = "CloudTrail Log Detections"
  description = "This detection_benchmark contains recommendations when scanning CloudTrail logs."
  type        = "detection"
  children = [
    detection.cloudtrail_log_cloudtrail_trail_updates,
    detection.cloudtrail_log_ec2_security_group_ingress_egress_updates,
    detection.cloudtrail_log_iam_root_console_logins,
  ]

  tags = merge(local.cloudtrail_log_common_tags, {
    type = "Benchmark"
  })
}

// Column blocks with base
detection "cloudtrail_log_base" {
  title = "CloudTrail Logs Base"

  /*
  columns {
    display = "none"
  }

  column "account_id" {
    display = "all"
  }

  column "actor" {
    display = "all"
  }

  column "operation" {
    display = "all"
  }

  column "region" {
    display = "all"
  }

  column "resource" {
    display = "all"
  }

  column "source_id" {
    display = "all"
  }

  column "source_ip" {
    display = "all"
  }

  column "timestamp" {
    display = "all"
  }
  */
}

detection "cloudtrail_log_iam_root_console_logins" {
  title       = "Check CloudTrail Logs for IAM Root Console Logins"
  description = "Detect IAM root user console logins to check for any actions performed by the root user."
  severity    = "high"
  query       = query.cloudtrail_log_iam_root_console_logins

  #references = [
  #  "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"
  #]

  tags = merge(local.cloudtrail_log_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "cloudtrail_log_cloudtrail_trail_updates" {
  title       = "Check CloudTrail Logs for CloudTrail Trail Updates"
  description = "Detect CloudTrail trail changes to check if logging was stopped."
  severity    = "medium"
  query       = query.cloudtrail_log_cloudtrail_trail_updates

  #references = [
  #  "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html",
  #  "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-delete-trails-console.html",
  #  "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-update-a-trail-console.html",
  #  "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-turning-off-logging.html"
  #]

  tags = merge(local.cloudtrail_log_common_tags, {
    mitre_attack_ids = "TA0005:T1562:001"
  })
}

detection "cloudtrail_log_ec2_security_group_ingress_egress_updates" {
  title       = "Check CloudTrail Logs for EC2 Security Group Ingress/Egress Updates"
  description = "Detect EC2 security group ingress and egress rule updates to check for unauthorized VPC access or export of data."
  severity    = "medium"
  query       = query.cloudtrail_log_ec2_security_group_ingress_egress_updates

  #references = [
  #  "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-security-groups.html",
  #  "https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/"
  #]

  tags = merge(local.cloudtrail_log_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0005:T1562"
  })
}

query "cloudtrail_log_cloudtrail_trail_updates" {
  sql = <<-EOQ
    select
      ${local.aws_cloudtrail_trail_update_detection_sql}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name in ('DeleteTrail', 'StopLogging', 'UpdateTrail')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_log_ec2_security_group_ingress_egress_updates" {
  sql = <<-EOQ
    select
      ${local.aws_ec2_security_group_ingress_egress_update_detection_sql}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('AuthorizeSecurityGroupEgress', 'AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'RevokeSecurityGroupIngress')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_log_iam_root_console_logins" {
  sql = <<-EOQ
    select
      ${local.aws_iam_root_console_login_detection_sql}
    from
      aws_cloudtrail_log
    where
      event_source = 'signin.amazonaws.com'
      and event_name = 'ConsoleLogin'
      and user_identity.type = 'Root'
      and (response_elements::JSON ->> 'ConsoleLogin') = 'Success'
    order by
      event_time desc;
  EOQ
}
