locals {
  cloudtrail_log_detection_iam_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/IAM"
  })

  cloudtrail_logs_detect_iam_entities_created_without_cloudformation_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "response_elements.role.arn")
  cloudtrail_logs_detect_iam_root_users_console_logins_sql_columns               = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "''")
  cloudtrail_logs_detect_iam_users_login_profile_updates_sql_columns             = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_iam_access_keys_creations_sql_columns                   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_iam_access_keys_deletions_sql_columns                   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_iam_users_with_password_change_sql_columns              = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", " ''")
  cloudtrail_logs_detect_iam_users_attached_to_admin_groups_sql_columns          = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_inline_policies_attached_to_iam_users_sql_columns       = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_managed_policies_attached_to_iam_users_sql_columns      = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_iam_role_policies_modifications_sql_columns             = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_iam_user_policies_modifications_sql_columns             = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_iam_group_policies_modifications_sql_columns            = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_iam_user_creations_sql_columns                          = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_iam_user_login_profile_creations_sql_columns            = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.userName")
  cloudtrail_logs_detect_managed_policies_attached_to_iam_roles_sql_columns      = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.roleName")
}

benchmark "cloudtrail_logs_iam_detections" {
  title       = "IAM Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's IAM logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_iam_access_keys_creations,
    detection.cloudtrail_logs_detect_iam_access_keys_deletions,
    detection.cloudtrail_logs_detect_iam_entities_created_without_cloudformation,
    detection.cloudtrail_logs_detect_iam_group_policies_modifications,
    detection.cloudtrail_logs_detect_iam_role_policies_modifications,
    detection.cloudtrail_logs_detect_iam_root_users_console_logins,
    detection.cloudtrail_logs_detect_iam_users_attached_to_admin_groups,
    detection.cloudtrail_logs_detect_iam_user_creations,
    detection.cloudtrail_logs_detect_iam_user_login_profile_creations,
    detection.cloudtrail_logs_detect_iam_users_login_profile_updates,
    detection.cloudtrail_logs_detect_iam_users_with_password_change,
    detection.cloudtrail_logs_detect_iam_user_policies_modifications,
    detection.cloudtrail_logs_detect_inline_policies_attached_to_iam_users,
    detection.cloudtrail_logs_detect_managed_policies_attached_to_iam_roles,
    detection.cloudtrail_logs_detect_managed_policies_attached_to_iam_users,
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

detection "cloudtrail_logs_detect_iam_users_login_profile_updates" {
  title       = "Detect IAM Users Login Profile Updates"
  description = "Detect IAM users login profile updates to check for password updates and usage."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_iam_users_login_profile_updates

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0003:T1098,TA0005:T1108,TA0005:T1550,TA0008:T1550"
  })
}

detection "cloudtrail_logs_detect_iam_root_users_console_logins" {
  title       = "Detect IAM Root Users Console Logins"
  description = "Detect IAM root users console logins to check for any actions performed by the root user."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_iam_root_users_console_logins

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "cloudtrail_logs_detect_iam_access_keys_creations" {
  title       = "Detect IAM Access Keys Creations"
  description = "Detect the creation of new IAM access keys for users, which may indicate legitimate user activity or potential credential compromise. Frequent or unauthorized access key creations can lead to unauthorized programmatic access and pose a security risk."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_iam_access_keys_creations

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0006:T1552.004, TA0008:T1550.001"
  })
}

detection "cloudtrail_logs_detect_iam_access_keys_deletions" {
  title       = "Detect IAM Access Keys Deletions"
  description = "Detect when IAM access keys are deleted. Deleting access keys can be a routine security practice, but unauthorized deletions may indicate an attempt to disrupt access or hide malicious activity."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_iam_access_keys_deletions

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0006:T1552.004"
  })
}

detection "cloudtrail_logs_detect_iam_users_with_password_change" {
  title       = "Detect IAM Users with Password Change"
  description = "Detect when an IAM user's password is changed. While password changes are common for legitimate purposes, unauthorized or unexpected changes may indicate credential compromise, brute-force attempts, or account takeover."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_iam_users_with_password_change

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0006:T1110"
  })
}

detection "cloudtrail_logs_detect_iam_users_attached_to_admin_groups" {
  title       = "Detect IAM Users Attached to Administrator Groups"
  description = "Detect when IAM users are attached to the administrators groups. This action may indicate privilege escalation attempts or unauthorized changes that could grant elevated permissions, potentially leading to full control over AWS resources."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_iam_users_attached_to_admin_groups

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "cloudtrail_logs_detect_inline_policies_attached_to_iam_users" {
  title       = "Detect Inline Policies Attached to IAM Users"
  description = "Detect when an inline policy is added to an IAM user. Adding inline policies can grant or modify permissions, potentially leading to privilege escalation or unauthorized access if done without proper authorization."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_inline_policies_attached_to_iam_users

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0004:T1098"
  })
}

detection "cloudtrail_logs_detect_managed_policies_attached_to_iam_users" {
  title       = "Detect Managed Policies Attached to IAM Users"
  description = "Detect when a managed policy is attached to an IAM user. Attaching managed policies can grant new permissions, potentially leading to privilege escalation or unauthorized access if the action is performed without proper authorization."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_managed_policies_attached_to_iam_users

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0004:T1098"
  })
}

detection "cloudtrail_logs_detect_managed_policies_attached_to_iam_roles" {
  title       = "Detect Managed Policies Attached to IAM Roles"
  description = "Detect when a managed policy is attached to an IAM role. Attaching managed policies to roles can grant or modify permissions, potentially leading to privilege escalation or unauthorized access if performed without proper authorization or oversight."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_managed_policies_attached_to_iam_roles

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0004:T1098"
  })
}

detection "cloudtrail_logs_detect_iam_role_policies_modifications" {
  title       = "Detect IAM Role Policies Modifications"
  description = "Detect when IAM role policies are modified. Unauthorized changes to role policies can grant or alter permissions, potentially enabling privilege escalation, weakening security controls, or facilitating malicious activity."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_iam_role_policies_modifications.md")
  query       = query.cloudtrail_logs_detect_iam_role_policies_modifications

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.001"
  })
}

detection "cloudtrail_logs_detect_iam_user_policies_modifications" {
  title       = "Detect IAM User Policies Modifications"
  description = "Detect when IAM user policies are modified. Unauthorized changes to user policies can grant excessive permissions, weaken security controls, or enable privilege escalation, potentially leading to unauthorized access or malicious activity."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_iam_user_policies_modifications.md")
  query       = query.cloudtrail_logs_detect_iam_user_policies_modifications

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.001"
  })
}

detection "cloudtrail_logs_detect_iam_group_policies_modifications" {
  title       = "Detect IAM Group Policies Modifications"
  description = "Detect when IAM group policies are modified. Unauthorized changes to group policies can escalate privileges, alter permissions for multiple users, or weaken security controls, potentially leading to unauthorized access or malicious activity."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_iam_group_policies_modifications.md")
  query       = query.cloudtrail_logs_detect_iam_group_policies_modifications

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

query "cloudtrail_logs_detect_iam_group_policies_modifications" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_group_policies_modifications_sql_columns}
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

query "cloudtrail_logs_detect_iam_role_policies_modifications" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_role_policies_modifications_sql_columns}
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

query "cloudtrail_logs_detect_iam_user_policies_modifications" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_user_policies_modifications_sql_columns}
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

query "cloudtrail_logs_detect_iam_root_users_console_logins" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_root_users_console_logins_sql_columns}
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

query "cloudtrail_logs_detect_iam_users_login_profile_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_users_login_profile_updates_sql_columns}
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


query "cloudtrail_logs_detect_iam_access_keys_creations" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_access_keys_creations_sql_columns}
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

query "cloudtrail_logs_detect_iam_access_keys_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_access_keys_deletions_sql_columns}
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

query "cloudtrail_logs_detect_iam_users_with_password_change" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_users_with_password_change_sql_columns}
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

query "cloudtrail_logs_detect_iam_users_attached_to_admin_groups" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_users_attached_to_admin_groups_sql_columns}
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

query "cloudtrail_logs_detect_inline_policies_attached_to_iam_users" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_inline_policies_attached_to_iam_users_sql_columns}
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

query "cloudtrail_logs_detect_managed_policies_attached_to_iam_users" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_managed_policies_attached_to_iam_users_sql_columns}
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

query "cloudtrail_logs_detect_managed_policies_attached_to_iam_roles" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_managed_policies_attached_to_iam_roles_sql_columns}
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