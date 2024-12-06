benchmark "cloudtrail_logs_iam_detections" {
  title       = "CloudTrail Log IAM Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's IAM logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_iam_entities_created_without_cloudformation,
    detection.cloudtrail_logs_detect_iam_root_console_logins,
    detection.cloudtrail_logs_detect_iam_user_login_profile_updates,
    detection.cloudtrail_logs_detect_iam_group_read_only_events,
    detection.cloudtrail_logs_detect_iam_policy_modified,
  ]
}

detection "cloudtrail_logs_detect_iam_entities_created_without_cloudformation" {
  title       = "Detect IAM Entities Created Without CloudFormation"
  description = "Detect IAM entities created without CloudFormation to check for mismanaged permissions."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_iam_entities_created_without_cloudformation

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "cloudtrail_logs_detect_iam_user_login_profile_updates" {
  title       = "Detect IAM User Login Profile Updates"
  description = "Detect IAM user login profile updates to check for password updates and usage."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_iam_user_login_profile_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1098,TA0005:T1108,TA0005:T1550,TA0008:T1550"
  })
}

detection "cloudtrail_logs_detect_iam_root_console_logins" {
  title       = "Detect IAM Root Console Logins"
  description = "Detect IAM root user console logins to check for any actions performed by the root user."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_iam_root_console_logins

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "cloudtrail_logs_detect_iam_group_read_only_events" {
  title       = "Detect IAM Group Read Only Event"
  description = "Detect IAM group read only event"
  severity    = "low"
  query       = query.cloudtrail_logs_detect_iam_group_read_only_events


  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
   })
}

detection "cloudtrail_logs_detect_iam_policy_modified" {
  title       = "Detect IAM Policy Modified"
  description = "Detect when IAM policy is modified."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_iam_policy_modified

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1548"
  })
}

query "cloudtrail_logs_detect_iam_entities_created_without_cloudformation" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_entities_created_without_cloudformation_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and (user_identity.invoked_by) != 'cloudformation.amazonaws.com'
      and event_name in ('BatchCreateUser', 'CreateGroup', 'CreateInstanceProfile', 'CreatePolicy', 'CreatePolicyVersion', 'CreateRole', 'CreateServiceLinkedRole', 'CreateUser')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_iam_root_console_logins" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_root_console_logins_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'signin.amazonaws.com'
      and event_name = 'ConsoleLogin'
      and (user_identity.type) = 'Root'
      and (response_elements.ConsoleLogin) = 'Success'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_iam_user_login_profile_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_user_login_profile_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'UpdateLoginProfile'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

// TODO: It does not reflect anything dangerous and can be removed
query "cloudtrail_logs_detect_iam_group_read_only_events" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_group_read_only_events_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name in ('GetGroup', 'GetGroupPolicy', 'ListAttachedGroupPolicies', 'ListGroupPolicies', 'ListGroups', 'ListGroupsForUser')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

// TODO: Break it down to individual resource, like role, group, user
query "cloudtrail_logs_detect_iam_policy_modified" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_policy_modified_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name in ('DeleteGroupPolicy', 'DeleteRolePolicy', 'DeleteUserPolicy', 'PutGroupPolicy', 'PutRolePolicy', 'PutUserPolicy', 'CreatePolicy', 'DeletePolicy', 'CreatePolicyVersion', 'DeletePolicyVersion', 'AttachRolePolicy', 'DetachRolePolicy', 'AttachUserPolicy', 'DetachUserPolicy', 'AttachGroupPolicy', 'DetachGroupPolicy')
      and error_code is null
    order by
      event_time desc;
  EOQ
}