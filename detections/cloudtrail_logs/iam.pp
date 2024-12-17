locals {
  cloudtrail_log_detection_iam_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/IAM"
  })

  cloudtrail_logs_detect_iam_entities_created_without_cloudformation_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "response_elements.role.arn")
  cloudtrail_logs_detect_iam_root_console_logins_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "''")
  cloudtrail_logs_detect_iam_user_login_profile_updates_sql_columns              = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_iam_access_key_creations_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_iam_access_key_deletions_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_iam_user_password_changes_sql_columns                    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", " ''")
  cloudtrail_logs_detect_iam_user_added_to_admin_groups_sql_columns                   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_inline_policies_added_to_iam_user_sql_columns                         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_managed_policies_attached_to_iam_user_sql_columns                   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_iam_role_policy_updates_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_iam_user_policy_updates_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_iam_group_policy_updates_sql_columns                    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_iam_user_creations_sql_columns                           = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_iam_user_login_profile_creations_sql_columns             = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_managed_policies_attached_to_iam_role_sql_columns        = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.roleName")
}

benchmark "cloudtrail_logs_iam_detections" {
  title       = "CloudTrail Log IAM Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's IAM logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_iam_access_key_creations,
    detection.cloudtrail_logs_detect_iam_access_key_deletions,
    detection.cloudtrail_logs_detect_iam_entities_created_without_cloudformation,
    detection.cloudtrail_logs_detect_iam_group_policy_updates,
    detection.cloudtrail_logs_detect_iam_role_policy_updates,
    detection.cloudtrail_logs_detect_iam_root_console_logins,
    detection.cloudtrail_logs_detect_iam_user_added_to_admin_groups,
    detection.cloudtrail_logs_detect_iam_user_creations,
    detection.cloudtrail_logs_detect_iam_user_login_profile_creations,
    detection.cloudtrail_logs_detect_iam_user_login_profile_updates,
    detection.cloudtrail_logs_detect_iam_user_password_changes,
    detection.cloudtrail_logs_detect_iam_user_policy_updates,
    detection.cloudtrail_logs_detect_inline_policies_added_to_iam_user,
    detection.cloudtrail_logs_detect_managed_policies_attached_to_iam_role,
    detection.cloudtrail_logs_detect_managed_policies_attached_to_iam_user,

  ]

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    type    = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_iam_entities_created_without_cloudformation" {
  title       = "Detect IAM Entities Created Without CloudFormation"
  description = "Detect IAM entities created without CloudFormation to check for mismanaged permissions."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_iam_entities_created_without_cloudformation

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "cloudtrail_logs_detect_iam_user_login_profile_updates" {
  title       = "Detect IAM Users Login Profile Updates"
  description = "Detect IAM users login profile updates to check for password updates and usage."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_iam_user_login_profile_updates

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0003:T1098,TA0005:T1108,TA0005:T1550,TA0008:T1550"
  })
}

detection "cloudtrail_logs_detect_iam_root_console_logins" {
  title       = "Detect IAM Root Users Console Logins"
  description = "Detect IAM root users console logins to check for any actions performed by the root user."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_iam_root_console_logins

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "cloudtrail_logs_detect_iam_access_key_creations" {
  title       = "Detect IAM Access Keys Creation"
  description = "Detect when new IAM access keys are created for user."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_iam_access_key_creations

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0006:T1552.004, TA0008:T1550.001"
  })
}

detection "cloudtrail_logs_detect_iam_access_key_deletions" {
  title       = "Detect IAM Access Keys Deletion"
  description = "Detect when IAM access keys are deleted."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_iam_access_key_deletions

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0006:T1552.004"
  })
}

detection "cloudtrail_logs_detect_iam_user_password_changes" {
  title       = "Detect IAM Users Password Change"
  description = "Detect when IAM users password are changed."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_iam_user_password_changes

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0006:T1110"
  })
}

detection "cloudtrail_logs_detect_iam_user_added_to_admin_groups" {
  title       = "Detect IAM Users Added to Administrator Groups"
  description = "Detect when IAM users are added to the Administrators groups."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_iam_user_added_to_admin_groups

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "cloudtrail_logs_detect_inline_policies_added_to_iam_user" {
  title       = "Detect Inline Policies Added to IAM User"
  description = "Detect when an inline policy is added to IAM user."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_inline_policies_added_to_iam_user

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0004:T1098"
  })
}

detection "cloudtrail_logs_detect_managed_policies_attached_to_iam_user" {
  title       = "Detect Managed Policy Attachment to IAM User"
  description = "Detect when a managed policy is attached to IAM user."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_managed_policies_attached_to_iam_user

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0004:T1098"
  })
}

detection "cloudtrail_logs_detect_managed_policies_attached_to_iam_role" {
  title       = "Detect Managed Policy Attachment to IAM Role"
  description = "Detect when a managed policy is attached to IAM role."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_managed_policies_attached_to_iam_role

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0004:T1098"
  })
}

detection "cloudtrail_logs_detect_iam_role_policy_updates" {
  title       = "Detect IAM Role Policy Modifications"
  description = "Detect unauthorized modifications to IAM policies or access rules."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_iam_role_policy_updates.md")
  query       = query.cloudtrail_logs_detect_iam_role_policy_updates

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.001"
  })
}

detection "cloudtrail_logs_detect_iam_user_policy_updates" {
  title       = "Detect IAM User Policy Modifications"
  description = "Detect unauthorized modifications to IAM user policies."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_iam_user_policy_updates.md")
  query       = query.cloudtrail_logs_detect_iam_user_policy_updates

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.001"
  })
}

detection "cloudtrail_logs_detect_iam_group_policy_updates" {
  title       = "Detect IAM Group Policy Modifications"
  description = "Detect unauthorized modifications to IAM group policies."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_iam_group_policy_updates.md")
  query       = query.cloudtrail_logs_detect_iam_group_policy_updates

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.002"
  })
}

detection "cloudtrail_logs_detect_iam_user_login_profile_creations" {
  title       = "Detect IAM User Login Profile Creations"
  description = "Detect when a login profile is created for an IAM user, enabling console access and potential persistence."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_iam_user_login_profile_creations

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0003:T1078"
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
      ${local.cloudtrail_log_detections_where_conditions}
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
      ${local.cloudtrail_log_detections_where_conditions}
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
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_iam_user_creations" {
  title       = "Detect New IAM Users Creation"
  description = "Detect when new IAM users are created."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_iam_user_creations

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
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
      ${local.cloudtrail_log_detections_where_conditions}
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
      ${local.cloudtrail_log_detections_where_conditions}
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
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}


query "cloudtrail_logs_detect_iam_access_key_creations" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_access_key_creations_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'CreateAccessKey'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_iam_access_key_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_access_key_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'DeleteAccessKey'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_iam_user_password_changes" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_user_password_changes_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'ChangePassword'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_iam_user_added_to_admin_groups" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_user_added_to_admin_groups_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'AddUserToGroup'
      and cast(request_parameters ->> 'groupName' as text) ilike '%admin%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_inline_policies_added_to_iam_user" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_inline_policies_added_to_iam_user_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'PutUserPolicy'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_managed_policies_attached_to_iam_user" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_managed_policies_attached_to_iam_user_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'AttachUserPolicy'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_managed_policies_attached_to_iam_role" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_managed_policies_attached_to_iam_role_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'AttachRolePolicy'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_iam_user_creations" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_user_creations_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'CreateUser'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_iam_user_login_profile_creations" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_user_login_profile_creations_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'CreateLoginProfile'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}