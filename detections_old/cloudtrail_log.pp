/*
detection_benchmark "cloudtrail_log_checks" {
  title       = "CloudTrail Log Detections"
  description = "This detection list contains recommendations when scanning CloudTrail logs."
  children = [
    detection_benchmark.cloudtrail_log_checks_ec2
  ]

  tags = merge(local.cloudtrail_log_common_tags, {
    type = "Benchmark"
  })
}

detection_benchmark "cloudtrail_log_checks_ec2" {
  title       = "CloudTrail Log Checks EC2"
  description = "This detection list contains recommendations for EC2 when scanning CloudTrail logs."
  children = [
    detection.cloudtrail_log_ec2_security_group_ingress_egress_updates
  ]

  tags = merge(local.cloudtrail_log_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudtrail_log_ec2_security_group_ingress_egress_updates" {
  title       = "EC2 Security Group Ingress/Egress Updates in CloudTrail Logs"
  description = "Detect EC2 security group ingress and egress rule updates to check for unauthorized VPC access or export of data."
  severity    = "low"
  query       = query.aws_ec2_security_group_ingress_egress_update_detection
  #author      = "cbruno"
  #references  = [
  #  "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-security-groups.html"
  #]

  tags = merge(local.cloudtrail_log_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0005:T1562"
  })
}
*/

// Using global params

/*
detection "cloudtrail_log_ec2_security_group_ingress_egress_updates" {
  title       = "EC2 Security Group Ingress/Egress Updates in CloudTrail Logs"
  description = "Detect EC2 security group ingress and egress rule updates to check for unauthorized VPC access or export of data."
  severity    = "low"
  query       = query.cloudtrail_log_ec2_security_group_ingress_egress_updates
  author      = "cbruno"
  references  = [
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-security-groups.html"
  ]

  args = [
    "start_time": param.start_time,
    "end_time": param.end_time,
    "account_id": param.account_id
  ]

  tags = merge(local.cloudtrail_log_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0005:T1562"
  })
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
      and timestamp between $1 and $2
      and account_id = $3
    order by
      event_time desc;
  EOQ

  param "start_time" {}
  param "end_time" {}
  param "account_id" {}
}
*/

// Already defined in controls/cloudtrail_log.pp
/*
locals {
  cloudtrail_log_common_tags = merge(local.aws_common_tags, {
    service = "AWS/CloudTrail"
  })
}
*/

// Test benchmark/detection with params and top level args

/*
benchmark "cloudtrail_log_checks" {
  title       = "CloudTrail Log Checks"
  description = "This detection list contains recommendations when scanning CloudTrail logs."
  type        = "detection"

  # TODO: Are there defaults? Descriptions?
  param "start_time" {}
  param "end_time" {}
  param "account_id" {}

  # TODO: Do we need args?
  args = [
    self.benchmark.param.cloudtrail_log_checks.start_time,
    self.benchmark.param.cloudtrail_log_checks.end_time,
    self.benchmark.param.cloudtrail_log_checks.account_id
  ]

  # TODO: Would args be better as a map to not require a specific order?
  args = {
    start_time: self.benchmark.param.cloudtrail_log_checks.start_time,
    end_time: self.benchmark.param.cloudtrail_log_checks.end_time,
    account_id: self.benchmark.param.cloudtrail_log_checks.account_id
  }

  children = [
    benchmark.cloudtrail_log_ec2_checks,
    detection.cloudtrail_log_iam_root_console_logins,
    detection.cloudtrail_log_iam_root_console_failed_logins,
  ]

  tags = merge(local.cloudtrail_log_common_tags, {
    type = "Benchmark"
  })
}

benchmark "cloudtrail_log_ec2_checks" {
  title       = "CloudTrail Log EC2 Checks"
  description = "This detection list contains recommendations for EC2 when scanning CloudTrail logs."
  type        = "detection"

  param "start_time" {}
  param "end_time" {}
  param "account_id" {}

  children = [
    detection.cloudtrail_log_ec2_security_group_ingress_egress_updates
  ]

  tags = merge(local.cloudtrail_log_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudtrail_log_ec2_security_group_ingress_egress_updates" {
  title       = "EC2 Security Group Ingress/Egress Updates in CloudTrail Logs"
  description = "Detect EC2 security group ingress and egress rule updates to check for unauthorized VPC access or export of data."
  severity    = "low"
  query       = query.cloudtrail_log_ec2_security_group_ingress_egress_updates
  author      = "cbruno"
  references  = [
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-security-groups.html"
  ]

  param "start_time" {}
  param "end_time" {}
  param "account_id" {}

  tags = merge(local.cloudtrail_log_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0005:T1562"
  })
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
      and timestamp between $1 and $2
      and account_id = $3
    order by
      event_time desc;
  EOQ

  param "start_time" {}
  param "end_time" {}
  param "account_id" {}
}
*/

// Test detection list/detection without params
/*
locals {
  # Store the replace logic in a local variable
  aws_ec2_security_group_ingress_egress_update_detection_sql = replace(local.common_dimensions_cloudtrail_log_sql, "__RESOURCE_SQL__", "request_parameters::JSON ->> 'groupId'")
}

detection_list "cloudtrail_log_checks" {
  title       = "CloudTrail Log Checks"
  description = "This detection list contains recommendations when scanning CloudTrail logs."
  children = [
    detection.cloudtrail_log_ec2_security_group_ingress_egress_updates,
    #detection.cloudtrail_log_iam_root_console_logins,
    #detection.cloudtrail_log_iam_root_console_failed_logins,
  ]

  tags = merge(local.cloudtrail_log_common_tags, {
    type = "Detection List"
  })
}

detection "cloudtrail_log_ec2_security_group_ingress_egress_updates" {
  title       = "EC2 Security Group Ingress/Egress Updates in CloudTrail Logs"
  description = "Detect EC2 security group ingress and egress rule updates to check for unauthorized VPC access or export of data."
  severity    = "low"
  query       = query.cloudtrail_log_ec2_security_group_ingress_egress_updates
  author      = "cbruno"
  references  = [
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-security-groups.html"
  ]

  tags = merge(local.cloudtrail_log_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0005:T1562"
  })
}

query "cloudtrail_log_ec2_security_group_ingress_egress_updates" {
  sql = <<-EOQ
    select
      ${local.aws_ec2_security_group_ingress_egress_update_detection_sql}
      -- Additional dimensions
      --additional_event_data,
      --request_parameters,
      --response_elements,
      --resources,
      --service_event_details,
      --user_agent,
      --user_identity
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
*/

/*
detection "cloudtrail_log_iam_root_console_logins" {
  title       = "IAM Root Console Logins in CloudTrail Logs"
  description = "Detect IAM root user console logins to check for any actions performed by the root user."
  severity    = "high"
  query       = query.cloudtrail_log_iam_root_console_logins_test
  author      = "cbruno"

  references  = [
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-tasks.html"
  ]

  tags = merge(local.cloudtrail_log_common_tags, {
    mitre_attack_tactic = "TA0004"
    mitre_attack_technique = "T1078"
  })
}

detection "cloudtrail_log_iam_root_console_failed_logins" {
  title       = "IAM Root Failed Console Logins in CloudTrail Logs"
  description = "Detect failed IAM root user console logins to check for brute force attacks or use of old credentials."
  severity    = "high"
  query       = query.cloudtrail_log_iam_root_console_failed_logins_test
  author      = "cbruno"

  references  = [
    "https://docs.panther.com/alerts/alert-runbooks/built-in-rules/aws-console-login-failed"
  ]

  # TODO: Add MITRE info
  # TODO: Should detection types be a top level property, tag?
  # TODO: How should we categorize them?
  tags = merge(local.cloudtrail_log_common_tags, {
    type = "failed attack"
  })
}

query "cloudtrail_log_iam_root_console_logins_test" {
  sql = <<-EOQ
    select
      -- Required detection fields
      tp_id as log_id,
      (to_timestamp(tp_timestamp/1000)::timestamptz)::varchar as event_time,
      -- Optional detection fields, depends on event type
      tp_source_ip as source_ip,
      user_identity.arn as actor,
      recipient_account_id as account_id,
      -- Additional fields, use any name
      user_identity.type as user_type
    from
      aws_cloudtrail_log
    where
      event_source = 'signin.amazonaws.com'
      and event_name = 'ConsoleLogin'
      and user_identity.type = 'Root'
      and (response_elements::JSON ->> 'ConsoleLogin') = 'Success'
    -- Detection results should be ordered by event time desc by default
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_log_iam_root_console_failed_logins_test" {
  sql = <<-EOQ
    select
      -- Required detection fields
      tp_id as log_id,
      (to_timestamp(tp_timestamp/1000)::timestamptz)::varchar as event_time,
      -- Optional detection fields, depends on event type
      tp_source_ip as source_ip,
      user_identity.arn as actor,
      recipient_account_id as account_id,
      error_code as error_code,
      -- Additional fields, use any name
      user_identity.type as user_type
    from
      aws_cloudtrail_log
    where
      event_source = 'signin.amazonaws.com'
      and event_name = 'ConsoleLogin'
      and user_identity.type = 'Root'
    -- Detection results should be ordered by event time desc by default
    order by
      event_time desc;
  EOQ
}
*/
