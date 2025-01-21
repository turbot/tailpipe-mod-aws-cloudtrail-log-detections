locals {
  iam_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/IAM"
  })
}

benchmark "iam_detections" {
  title       = "IAM Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for IAM events."
  type        = "detection"
  children = [
    detection.iam_access_key_created,
    detection.iam_access_key_deleted,
    detection.iam_entity_created_without_cloudformation,
    detection.iam_group_inline_policy_created,
    detection.iam_role_inline_policy_created,
    detection.iam_role_managed_policy_attached,
    detection.iam_root_user_console_login,
    detection.iam_user_added_to_administrator_group,
    detection.iam_user_administrative_password_reset,
    detection.iam_user_console_access_enabled,
    detection.iam_user_created,
    detection.iam_user_email_address_updated,
    detection.iam_user_inline_policy_attached,
    detection.iam_user_inline_policy_created,
    detection.iam_user_managed_policy_attached,
    detection.iam_user_mfa_disabled,
    detection.iam_user_password_changed,
  ]

  tags = merge(local.iam_common_tags, {
    type = "Benchmark"
  })
}

detection "iam_user_mfa_disabled" {
  title           = "IAM User MFA Disabled"
  description     = "Detect when MFA was disabled for an IAM user through login profile updates. Disabling MFA weakens security controls, potentially exposing accounts to unauthorized access."
  documentation   = file("./detections/docs/iam_user_mfa_disabled.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.iam_user_mfa_disabled

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0005:T1078"
  })
}

query "iam_user_mfa_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_user_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'UpdateLoginProfile'
      and (request_parameters -> 'mfaSettings') = 'disabled'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "iam_user_console_access_enabled" {
  title           = "IAM User Console Access Enabled"
  description     = "Detect when console access was enabled for an IAM user through login profile updates, potentially increasing attack surfaces if credentials were compromised."
  documentation   = file("./detections/docs/iam_user_console_access_enabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.iam_user_console_access_enabled

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "iam_user_console_access_enabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_user_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'UpdateLoginProfile'
      and (request_parameters -> 'createLoginProfile') = true
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "iam_user_email_address_updated" {
  title           = "IAM User Email Address Updated"
  description     = "Detect when an email address was updated for an IAM user in a login profile. This action may indicate attempts to hijack account recovery mechanisms or modify user identities."
  documentation   = file("./detections/docs/iam_user_email_address_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.iam_user_email_address_updated

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0006:T1098"
  })
}

query "iam_user_email_address_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_user_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'UpdateLoginProfile'
      and (request_parameters ->> 'email') IS NOT NULL
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "iam_entity_created_without_cloudformation" {
  title           = "IAM Entity Created Without CloudFormation"
  description     = "Detect when an IAM entity was created without using CloudFormation. This action may indicate mismanaged permissions or deviations from infrastructure-as-code practices."
  documentation   = file("./detections/docs/iam_entity_created_without_cloudformation.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.iam_entity_created_without_cloudformation

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

query "iam_entity_created_without_cloudformation" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_role_arn}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name in (
        'BatchCreateUser', 
        'CreateGroup', 
        'CreateInstanceProfile', 
        'CreatePolicy', 
        'CreatePolicyVersion', 
        'CreateRole', 
        'CreateServiceLinkedRole', 
        'CreateUser'
      )
      and user_identity.invoked_by != 'cloudformation.amazonaws.com'
      ${local.detection_sql_where_conditions}
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

detection "iam_user_administrative_password_reset" {
  title           = "IAM User Administrative Password Reset"
  description     = "Detect when an IAM user's password was reset via a login profile update. This detection focuses on administrative actions that may indicate credential compromise, unauthorized access attempts, or privilege escalation activities. This complements user-initiated password changes monitored by 'ChangePassword' events."
  documentation   = file("./detections/docs/iam_user_administrative_password_reset.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.iam_user_administrative_password_reset

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0006:T1098,TA0005:T1108,TA0005:T1550,TA0008:T1078"
  })
}

query "iam_user_administrative_password_reset" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_user_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'UpdateLoginProfile'
      and (request_parameters ->> 'password') IS NOT NULL
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "iam_user_password_changed" {
  title           = "IAM User Password Changed"
  description     = "Detect when an IAM user's password was changed. While password changes are common for legitimate purposes, unauthorized or unexpected changes may indicate credential compromise, brute-force attempts, or account takeover."
  documentation   = file("./detections/docs/iam_user_password_changed.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.iam_user_password_changed

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0006:T1110"
  })
}

query "iam_user_password_changed" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_user_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'ChangePassword'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "iam_root_user_console_login" {
  title           = "IAM Root User Console Login"
  description     = "Detect when the IAM root user logged in via the AWS Management Console. Monitoring root user activity is critical due to the elevated permissions associated with root accounts, as such logins may indicate unauthorized access, privilege escalation attempts, or credential compromise."
  documentation   = file("./detections/docs/iam_root_user_console_login.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.iam_root_user_console_login

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

query "iam_root_user_console_login" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_user_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'signin.amazonaws.com'
      and event_name = 'ConsoleLogin'
      and user_identity.type = 'Root'
      and (response_elements ->> 'ConsoleLogin') = 'Success'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "iam_access_key_created" {
  title           = "IAM Access Key Created"
  description     = "Detect when an IAM access key was created for a user. While access key creation may indicate legitimate user activity, frequent or unauthorized access key creations could lead to credential compromise and unauthorized programmatic access, posing a security risk."
  documentation   = file("./detections/docs/iam_access_key_created.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.iam_access_key_created

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0006:T1552.004, TA0008:T1550.001"
  })
}

query "iam_access_key_created" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_user_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'CreateAccessKey'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "iam_access_key_deleted" {
  title           = "IAM Access Key Deleted"
  description     = "Detect when an IAM access key was deleted. Deleting access keys may be part of routine security practices, but unauthorized deletions could indicate an attempt to disrupt access or conceal malicious activity."
  documentation   = file("./detections/docs/iam_access_key_deleted.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.iam_access_key_deleted

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0006:T1552.004"
  })
}

query "iam_access_key_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_user_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'DeleteAccessKey'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "iam_user_added_to_administrator_group" {
  title           = "IAM User Added to Administrator Group"
  description     = "Detect when an IAM user was added to an administrator group. This action may indicate privilege escalation attempts or unauthorized changes, potentially granting elevated permissions and leading to full control over AWS resources."
  documentation   = file("./detections/docs/iam_user_added_to_administrator_group.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.iam_user_added_to_administrator_group

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

query "iam_user_added_to_administrator_group" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_user_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'AddUserToGroup'
      and (request_parameters ->> 'groupName') ilike '%admin%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "iam_user_inline_policy_attached" {
  title           = "IAM User Inline Policy Attached"
  description     = "Detect when an inline policy was attached to an IAM user. Adding inline policies can grant or modify permissions, potentially leading to privilege escalation or unauthorized access if done without proper authorization."
  documentation   = file("./detections/docs/iam_user_inline_policy_attached.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.iam_user_inline_policy_attached

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0004:T1098"
  })
}

query "iam_user_inline_policy_attached" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_user_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'PutUserPolicy'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "iam_user_managed_policy_attached" {
  title           = "IAM User Managed Policy Attached"
  description     = "Detect when a managed policy was attached to an IAM user. Attaching managed policies can grant new permissions, potentially leading to privilege escalation or unauthorized access if done without proper authorization."
  documentation   = file("./detections/docs/iam_user_managed_policy_attached.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.iam_user_managed_policy_attached

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0004:T1098"
  })
}

query "iam_user_managed_policy_attached" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_user_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'AttachUserPolicy'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "iam_role_managed_policy_attached" {
  title           = "IAM Role Managed Policy Attached"
  description     = "Detect when a managed policy was attached to an IAM role. Attaching managed policies to roles can grant or modify permissions, potentially leading to privilege escalation or unauthorized access if performed without proper authorization or oversight."
  documentation   = file("./detections/docs/iam_role_managed_policy_attached.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.iam_role_managed_policy_attached

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0004:T1098"
  })
}

query "iam_role_managed_policy_attached" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_role_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'AttachRolePolicy'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "iam_role_inline_policy_created" {
  title           = "IAM Role Inline Policy Created"
  description     = "Detect when an inline policy was created for an IAM role. Inline policies granting administrative privileges may allow unauthorized privilege escalation or security bypass, enabling attackers to perform sensitive actions."
  documentation   = file("./detections/docs/iam_role_inline_policy_created.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.iam_role_inline_policy_created

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.001, TA0004:T1098"
  })
}

query "iam_role_inline_policy_created" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_role_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'PutRolePolicy'
      and (request_parameters ->> 'PolicyName') IS NOT NULL
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "iam_user_inline_policy_created" {
  title           = "IAM User Inline Policy Created"
  description     = "Detect when an inline policy was created for an IAM user. Inline policies may bypass centralized controls and lead to privilege escalation or security misconfigurations."
  documentation   = file("./detections/docs/iam_user_inline_policy_created.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.iam_user_inline_policy_created

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.001, TA0003:T1098"
  })
}

query "iam_user_inline_policy_created" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_policy_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'PutUserPolicy'
      and (request_parameters ->> 'PolicyName') IS NOT NULL
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "iam_group_inline_policy_created" {
  title           = "IAM Group Inline Policy Created"
  description     = "Detect when an inline policy was created for an IAM group. Inline policies may bypass centralized controls and lead to privilege escalation or security misconfigurations."
  documentation   = file("./detections/docs/iam_group_inline_policy_created.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.iam_group_inline_policy_created

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0040:T1484.002, TA0003:T1098"
  })
}

query "iam_group_inline_policy_created" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_policy_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'PutGroupPolicy'
      and (request_parameters ->> 'PolicyName') IS NOT NULL
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "iam_user_created" {
  title           = "IAM User Created"
  description     = "Detect when a new IAM user was created. Unauthorized user creation may indicate privilege escalation attempts, credential compromise, or lateral movement, potentially leading to unauthorized access and malicious activity."
  documentation   = file("./detections/docs/iam_user_created.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.iam_user_created

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

query "iam_user_created" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_user_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'iam.amazonaws.com'
      and event_name = 'CreateUser'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}
