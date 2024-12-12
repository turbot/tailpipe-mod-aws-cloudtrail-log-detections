locals {
  cloudtrail_logs_detect_iam_group_read_only_events_sql_columns                  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.groupName")
  cloudtrail_logs_detect_iam_policy_modified_sql_columns                         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.policyArn")
  cloudtrail_logs_detect_iam_entities_created_without_cloudformation_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "response_elements.role.arn")
  cloudtrail_logs_detect_iam_root_console_logins_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "''")
  cloudtrail_logs_detect_iam_user_login_profile_updates_sql_columns              = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_iam_access_key_creation_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_iam_access_key_deletion_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_iam_user_password_change_sql_columns                    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", " ''")
  cloudtrail_logs_detect_user_added_to_admin_group_sql_columns                   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_inline_policy_added_sql_columns                         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_managed_policy_attachment_sql_columns                   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "coalesce(request_parameters.userName, request_parameters.roleName)")
  cloudtrail_logs_detect_iam_role_policy_updates_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_iam_user_policy_updates_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_iam_group_policy_updates_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

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
    detection.cloudtrail_logs_detect_iam_access_key_creation,
    detection.cloudtrail_logs_detect_iam_role_policy_updates,
    detection.cloudtrail_logs_detect_iam_user_policy_updates,
    detection.cloudtrail_logs_detect_iam_group_policy_updates,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/IAM"
  })
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

detection "cloudtrail_logs_detect_iam_access_key_creation" {
  title       = "Detect IAM Access Key Creation"
  description = "Detect when a new IAM access key is created for a user."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_iam_access_key_creation

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1552.004"
  })
}

detection "cloudtrail_logs_detect_iam_access_key_deletion" {
  title       = "Detect IAM Access Key Deletion"
  description = "Detect when an IAM access key is deleted."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_iam_access_key_deletion

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1552.004"
  })
}

detection "cloudtrail_logs_detect_iam_user_password_change" {
  title       = "Detect IAM User Password Change"
  description = "Detect when an IAM user's password is changed."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_iam_user_password_change

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1110"
  })
}

detection "cloudtrail_logs_detect_user_added_to_admin_group" {
  title       = "Detect IAM User Added to Administrator Group"
  description = "Detect when an IAM user is added to the Administrators group."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_user_added_to_admin_group

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "cloudtrail_logs_detect_inline_policy_added" {
  title       = "Detect Inline Policy Added to IAM User"
  description = "Detect when an inline policy is added to an IAM user."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_inline_policy_added

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1098"
  })
}

detection "cloudtrail_logs_detect_managed_policy_attachment" {
  title       = "Detect Managed Policy Attachment to IAM User or Role"
  description = "Detect when a managed policy is attached to an IAM user or role."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_managed_policy_attachment

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1098"
  })
}

detection "cloudtrail_logs_detect_iam_role_policy_updates" {
  title       = "Detect Domain Policy Modifications"
  description = "Detect unauthorized modifications to IAM policies or access rules."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_iam_role_policy_updates.md")
  query       = query.cloudtrail_logs_detect_iam_role_policy_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1484.001"
  })
}

detection "cloudtrail_logs_detect_iam_user_policy_updates" {
  title       = "Detect Domain Policy Modifications"
  description = "Detect unauthorized modifications to IAM policies or access rules."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_iam_user_policy_updates.md")
  query       = query.cloudtrail_logs_detect_iam_user_policy_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1484.001"
  })
}

detection "cloudtrail_logs_detect_iam_group_policy_updates" {
  title       = "Detect Group Policy Modifications"
  description = "Detect unauthorized modifications to IAM group policies."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_iam_group_policy_updates.md")
  query       = query.cloudtrail_logs_detect_iam_group_policy_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1484.002"
  })
}

query "cloudtrail_logs_detect_iam_group_policy_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_group_policy_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name in ('PutGroupPolicy', 'AttachGroupPolicy')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_iam_role_policy_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_role_policy_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'PutRolePolicy'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_iam_user_policy_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_user_policy_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'PutUserPolicy'
      and error_code is null
    order by
      event_time desc;
  EOQ
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

query "cloudtrail_logs_detect_iam_access_key_creation" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_access_key_creation_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'CreateAccessKey'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_iam_access_key_deletion" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_access_key_deletion_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'DeleteAccessKey'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_iam_user_password_change" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_user_password_change_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'ChangePassword'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_user_added_to_admin_group" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_user_added_to_admin_group_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'AddUserToGroup'
      and cast(request_parameters ->> 'groupName' as text) ilike '%admin%'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_inline_policy_added" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_inline_policy_added_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'PutUserPolicy'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_managed_policy_attachment" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_managed_policy_attachment_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name in ('AttachUserPolicy', 'AttachRolePolicy')
      and error_code is null
    order by
      event_time desc;
  EOQ
}
