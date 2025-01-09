locals {
  cloudtrail_log_detection_iam_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/IAM"
  })

  cloudtrail_logs_detect_iam_users_attached_to_admin_groups_sql_columns            = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.userName')")
  cloudtrail_logs_detect_iam_role_policies_modifications_sql_columns               = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  cloudtrail_logs_detect_iam_access_key_creations_sql_columns                      = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.userName')")
  cloudtrail_logs_detect_iam_access_key_deletions_sql_columns                      = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.userName')")
  cloudtrail_logs_detect_iam_entities_created_without_cloudformation_sql_columns   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(response_elements, '$.role.arn')")
  cloudtrail_logs_detect_iam_group_policies_modifications_sql_columns              = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  cloudtrail_logs_detect_iam_role_policy_modifications_sql_columns                 = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  cloudtrail_logs_detect_iam_root_user_console_logins_sql_columns                  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "''")
  cloudtrail_logs_detect_iam_user_creations_sql_columns                            = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.userName')")
  cloudtrail_logs_detect_iam_user_login_profile_creations_sql_columns              = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.userName')")
  cloudtrail_logs_detect_iam_user_policy_modifications_sql_columns                 = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  cloudtrail_logs_detect_iam_users_attached_to_administrator_groups_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.userName')")
  cloudtrail_logs_detect_iam_users_with_administrative_password_resets_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.userName')")
  cloudtrail_logs_detect_iam_users_with_password_change_sql_columns                = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", " ''")
  cloudtrail_logs_detect_inline_policies_attached_to_iam_users_sql_columns         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.userName')")
  cloudtrail_logs_detect_managed_policies_attached_to_iam_roles_sql_columns        = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.roleName')")
  cloudtrail_logs_detect_managed_policies_attached_to_iam_users_sql_columns        = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.userName')")
  cloudtrail_logs_detect_iam_users_login_profile_updates_sql_columns               = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.userName')")
}

benchmark "cloudtrail_logs_iam_detections" {
  title       = "IAM Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for IAM events."
  type        = "detection"
  children = [
    detection.cloudtrail_logs_detect_iam_access_key_creations,
    detection.cloudtrail_logs_detect_iam_access_key_deletions,
    detection.cloudtrail_logs_detect_iam_entities_created_without_cloudformation,
    detection.cloudtrail_logs_detect_iam_root_user_console_logins,
    detection.cloudtrail_logs_detect_iam_user_creations,
    detection.cloudtrail_logs_detect_iam_users_attached_to_administrator_groups,
    detection.cloudtrail_logs_detect_iam_users_with_administrative_password_resets,
    detection.cloudtrail_logs_detect_iam_users_with_password_change,
    detection.cloudtrail_logs_detect_inline_policies_attached_to_iam_users,
    detection.cloudtrail_logs_detect_managed_policies_attached_to_iam_roles,
    detection.cloudtrail_logs_detect_managed_policies_attached_to_iam_users,
    detection.cloudtrail_logs_detect_iam_users_with_console_access_enabled,
    detection.cloudtrail_logs_detect_iam_users_with_email_address_updates,
    detection.cloudtrail_logs_detect_iam_users_with_mfa_disabled,
    detection.cloudtrail_logs_detect_public_access_granted_to_iam_roles,
    detection.cloudtrail_logs_detect_public_access_granted_to_iam_users,
    detection.cloudtrail_logs_detect_admin_access_granted_to_iam_roles,
    detection.cloudtrail_logs_detect_admin_access_granted_to_iam_users,
    detection.cloudtrail_logs_detect_iam_role_inline_policy_creations,
    detection.cloudtrail_logs_detect_public_access_granted_to_iam_groups,
    detection.cloudtrail_logs_detect_admin_access_granted_to_iam_groups,
  ]

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_iam_users_with_mfa_disabled" {
  title           = "Detect IAM Users with MFA Disabled"
  description     = "Detect IAM users where MFA is disabled via login profile updates, potentially exposing accounts to unauthorized access due to weakened security controls."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_iam_users_with_mfa_disabled

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0005:T1078"
  })
}

query "cloudtrail_logs_detect_iam_users_with_mfa_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_users_login_profile_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'UpdateLoginProfile'
      and json_extract_string(request_parameters, '$.mfaSettings') = 'disabled'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_iam_users_with_console_access_enabled" {
  title           = "Detect IAM Users with Console Access Enabled"
  description     = "Detect IAM users where console access is enabled via login profile updates, which may increase attack surfaces if credentials are compromised."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_iam_users_with_console_access_enabled

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "cloudtrail_logs_detect_iam_users_with_console_access_enabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_users_login_profile_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'UpdateLoginProfile'
      and json_extract_string(request_parameters, '$.createLoginProfile') = 'true'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_iam_users_with_email_address_updates" {
  title           = "Detect IAM Users with Email Address Updates"
  description     = "Detect IAM users with email address updates in login profiles, which may indicate attempts to hijack account recovery mechanisms or modify user identities."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_iam_users_with_email_address_updates

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0006:T1098"
  })
}

query "cloudtrail_logs_detect_iam_users_with_email_address_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_users_login_profile_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'UpdateLoginProfile'
      and json_extract_string(request_parameters, '$.email') IS NOT NULL
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_iam_entities_created_without_cloudformation" {
  title           = "Detect IAM Entities Created Without CloudFormation"
  description     = "Detect IAM entities created without CloudFormation to check for mismanaged permissions."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_iam_entities_created_without_cloudformation

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
      and event_name in ('BatchCreateUser', 'CreateGroup', 'CreateInstanceProfile', 'CreatePolicy', 'CreatePolicyVersion', 'CreateRole', 'CreateServiceLinkedRole', 'CreateUser')
      and user_identity.invoked_by != 'cloudformation.amazonaws.com'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

/*
Event Name: UpdateLoginProfile
Focus: Detects when a login profile (used for password-based authentication) is updated and specifically checks for changes where a password is set or reset.
Purpose: This targets administrative actions on IAM user profiles, such as resetting passwords for users, which may indicate privilege escalation attempts or unauthorized modifications.

Event Name: ChangePassword
Focus: Tracks self-service password changes performed directly by IAM users.
Purpose: This detects user-initiated actions rather than administrative updates, focusing on potential insider actions like unauthorized password changes.
*/

detection "cloudtrail_logs_detect_iam_users_with_administrative_password_resets" {
  title           = "Detect IAM Users with Administrative Password Resets"
  description     = "Detect IAM users password resets via login profile updates, focusing on administrative actions that may indicate credential compromise, unauthorized access attempts, or privilege escalation activities. This detection complements user-initiated password changes monitored by 'ChangePassword' events."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_iam_users_with_administrative_password_resets

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0006:T1098,TA0005:T1108,TA0005:T1550,TA0008:T1078"
  })
}

query "cloudtrail_logs_detect_iam_users_with_administrative_password_resets" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_users_with_administrative_password_resets_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'UpdateLoginProfile'
      and json_extract_string(request_parameters, '$.password') IS NOT NULL
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_iam_users_with_password_change" {
  title           = "Detect IAM Users with Password Change"
  description     = "Detect when an IAM user's password is changed. While password changes are common for legitimate purposes, unauthorized or unexpected changes may indicate credential compromise, brute-force attempts, or account takeover."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_iam_users_with_password_change

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0006:T1110"
  })
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

detection "cloudtrail_logs_detect_iam_root_user_console_logins" {
  title           = "Detect IAM Root User Console Logins"
  description     = "Detect IAM root user console logins to monitor actions performed by the root user, which may indicate unauthorized access, privilege escalation attempts, or credential compromise due to the elevated permissions associated with root accounts."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_iam_root_user_console_logins

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

query "cloudtrail_logs_detect_iam_root_user_console_logins" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_root_user_console_logins_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'signin.amazonaws.com'
      and event_name = 'ConsoleLogin'
      and user_identity.type = 'Root'
      and json_extract_string(response_elements, '$.ConsoleLogin') = 'Success'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_iam_access_key_creations" {
  title           = "Detect IAM Access Key Creations"
  description     = "Detect the creation of new IAM access keys for users, which may indicate legitimate user activity or potential credential compromise. Frequent or unauthorized access key creations can lead to unauthorized programmatic access and pose a security risk."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_iam_access_key_creations

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0006:T1552.004, TA0008:T1550.001"
  })
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

detection "cloudtrail_logs_detect_iam_access_key_deletions" {
  title           = "Detect IAM Access Key Deletions"
  description     = "Detect when IAM access keys are deleted. Deleting access keys can be a routine security practice, but unauthorized deletions may indicate an attempt to disrupt access or hide malicious activity."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_iam_access_key_deletions

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0006:T1552.004"
  })
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

detection "cloudtrail_logs_detect_iam_users_attached_to_administrator_groups" {
  title           = "Detect IAM Users Attached to Administrator Groups"
  description     = "Detect when IAM users are attached to the administrators groups. This action may indicate privilege escalation attempts or unauthorized changes that could grant elevated permissions, potentially leading to full control over AWS resources."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_iam_users_attached_to_administrator_groups

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

query "cloudtrail_logs_detect_iam_users_attached_to_administrator_groups" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_users_attached_to_administrator_groups_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'AddUserToGroup'
      and json_extract_string(request_parameters, '$.groupName') ilike '%admin%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_inline_policies_attached_to_iam_users" {
  title           = "Detect Inline Policies Attached to IAM Users"
  description     = "Detect when an inline policy is added to an IAM user. Adding inline policies can grant or modify permissions, potentially leading to privilege escalation or unauthorized access if done without proper authorization."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_inline_policies_attached_to_iam_users

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0004:T1098"
  })
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

detection "cloudtrail_logs_detect_managed_policies_attached_to_iam_users" {
  title           = "Detect Managed Policies Attached to IAM Users"
  description     = "Detect when a managed policy is attached to an IAM user. Attaching managed policies can grant new permissions, potentially leading to privilege escalation or unauthorized access if the action is performed without proper authorization."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_managed_policies_attached_to_iam_users

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0004:T1098"
  })
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

detection "cloudtrail_logs_detect_managed_policies_attached_to_iam_roles" {
  title           = "Detect Managed Policies Attached to IAM Roles"
  description     = "Detect when a managed policy is attached to an IAM role. Attaching managed policies to roles can grant or modify permissions, potentially leading to privilege escalation or unauthorized access if performed without proper authorization or oversight."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_managed_policies_attached_to_iam_roles

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0004:T1098"
  })
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

detection "cloudtrail_logs_detect_public_access_granted_to_iam_roles" {
  title           = "Detect Public Access Granted to IAM Roles"
  description     = "Detect when an IAM role policy is modified to grant public access. Publicly accessible IAM roles may expose sensitive permissions or allow unauthorized actions, leading to privilege escalation or data compromise."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_public_access_granted_to_iam_roles

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.001, TA0003:T1098"
  })
}

query "cloudtrail_logs_detect_public_access_granted_to_iam_roles" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_role_policies_modifications_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'PutRolePolicy'
      and (
        -- Detect wildcard principals granting public access
        json_extract_string(request_parameters, '$.PolicyDocument') like '%"Principal":"*"%'

        -- Detect AWS wildcard principals granting cross-account access
        or json_extract_string(request_parameters, '$.PolicyDocument') like '%"Principal":{"AWS":"*"}%'
      )
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_admin_access_granted_to_iam_roles" {
  title           = "Detect Admin Access Granted to IAM Roles"
  description     = "Detect when an IAM role policy is modified to grant administrative privileges. IAM roles with admin access may allow unauthorized privilege escalation or security bypass, enabling attackers to perform sensitive actions."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_admin_access_granted_to_iam_roles

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.001, TA0004:T1098"
  })
}

query "cloudtrail_logs_detect_admin_access_granted_to_iam_roles" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_role_policies_modifications_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'PutRolePolicy'
      and json_extract_string(request_parameters, '$.PolicyDocument') like '%"Action":"iam:*"%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_iam_role_inline_policy_creations" {
  title           = "Detect IAM Role Inline Policy Creations"
  description     = "Detect when an IAM role policy is modified to grant administrative privileges. IAM roles with admin access may allow unauthorized privilege escalation or security bypass, enabling attackers to perform sensitive actions."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_admin_access_granted_to_iam_roles

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.001, TA0004:T1098"
  })
}

query "cloudtrail_logs_detect_iam_role_inline_policy_creations" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_role_policies_modifications_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'PutRolePolicy'
      and json_extract_string(request_parameters, '$.PolicyDocument') like '%"Action":"iam:*"%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_public_access_granted_to_iam_users" {
  title           = "Detect Public Access Granted to IAM Users"
  description     = "Detect when an IAM user policy is modified to grant public access. Publicly accessible IAM users may expose sensitive permissions or allow unauthorized actions, leading to privilege escalation or data compromise."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_public_access_granted_to_iam_users

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.001, TA0003:T1098"
  })
}

query "cloudtrail_logs_detect_public_access_granted_to_iam_users" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_user_policy_modifications_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'PutUserPolicy'
      and (
        -- Detect wildcard principals granting public access
        json_extract_string(request_parameters, '$.PolicyDocument') like '%"Principal":"*"%'

        -- Detect AWS wildcard principals granting cross-account access
        or json_extract_string(request_parameters, '$.PolicyDocument') like '%"Principal":{"AWS":"*"}%'
      )
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_admin_access_granted_to_iam_users" {
  title           = "Detect Admin Access Granted to IAM Users"
  description     = "Detect when an IAM user policy is modified to grant administrative privileges. IAM users with admin access may allow unauthorized privilege escalation or security bypass, enabling attackers to perform sensitive actions."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_admin_access_granted_to_iam_users

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.001, TA0004:T1098"
  })
}

query "cloudtrail_logs_detect_admin_access_granted_to_iam_users" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_user_policy_modifications_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'PutUserPolicy'
      and json_extract_string(request_parameters, '$.PolicyDocument') like '%"Action":"iam:*"%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_iam_user_inline_policy_creations" {
  title           = "Detect IAM User Inline Policy Creations"
  description     = "Detect IAM user modifications with newly created inline policies, which may bypass centralized controls and lead to privilege escalation or security misconfigurations."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_iam_user_inline_policy_creations

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.001, TA0003:T1098"
  })
}

query "cloudtrail_logs_detect_iam_user_inline_policy_creations" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_user_policy_modifications_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'PutUserPolicy'
      and json_extract_string(request_parameters, '$.PolicyName') IS NOT NULL
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_public_access_granted_to_iam_groups" {
  title           = "Detect Public Access Granted to IAM Groups"
  description     = "Detect when an IAM group policy is modified to grant public access. Publicly accessible IAM groups may expose sensitive permissions or allow unauthorized actions, leading to privilege escalation or data compromise."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_public_access_granted_to_iam_groups

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.002, TA0003:T1098"
  })
}

query "cloudtrail_logs_detect_public_access_granted_to_iam_groups" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_group_policies_modifications_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name in ('PutGroupPolicy', 'AttachGroupPolicy')
      and (
        -- Detect wildcard principals granting public access
        json_extract_string(request_parameters, '$.PolicyDocument') like '%"Principal":"*"%'

        -- Detect AWS wildcard principals granting cross-account access
        or json_extract_string(request_parameters, '$.PolicyDocument') like '%"Principal":{"AWS":"*"}%'
      )
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_admin_access_granted_to_iam_groups" {
  title           = "Detect Admin Access Granted to IAM Groups"
  description     = "Detect when an IAM group policy is modified to grant administrative privileges. IAM groups with admin access may allow unauthorized privilege escalation or security bypass, enabling attackers to perform sensitive actions."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_admin_access_granted_to_iam_groups

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.002, TA0004:T1098"
  })
}

query "cloudtrail_logs_detect_admin_access_granted_to_iam_groups" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_group_policies_modifications_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name in ('PutGroupPolicy', 'AttachGroupPolicy')
      and json_extract_string(request_parameters, '$.PolicyDocument') like '%"Action":"iam:*"%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_iam_group_inline_policy_creations" {
  title           = "Detect IAM Group Inline Policy Creations"
  description     = "Detect IAM group modifications with newly created inline policies, which may bypass centralized controls and lead to privilege escalation or security misconfigurations."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_iam_group_inline_policy_creations

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.002, TA0003:T1098"
  })
}

query "cloudtrail_logs_detect_iam_group_inline_policy_creations" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_iam_group_policies_modifications_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'PutGroupPolicy'
      and json_extract_string(request_parameters, '$.PolicyName') IS NOT NULL
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_iam_user_creations" {
  title           = "Detect IAM User Creations"
  description     = "Detect when new IAM users are created. Unauthorized user creation may indicate privilege escalation attempts, credential compromise, or lateral movement, potentially leading to unauthorized access and malicious activity."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_iam_user_creations

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
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

detection "cloudtrail_logs_detect_iam_users_attached_to_admin_groups" {
  title           = "Detect IAM Users Attached to Administrator Groups"
  description     = "Detect when IAM users are attached to the administrators groups. This action may indicate privilege escalation attempts or unauthorized changes that could grant elevated permissions, potentially leading to full control over AWS resources."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_iam_users_attached_to_admin_groups

  tags = merge(local.cloudtrail_log_detection_iam_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
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
      and json_extract_string(request_parameters, '$.groupName') ilike '%admin%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}