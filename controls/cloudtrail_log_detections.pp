/*
 * Required fields:
 * - tp_id/log_id: Used for uniqueness and to correlate back to tailpipe row)
 * - event_time: Event timestamp (in UTC?)
 * Optional fields:
 * - source_ip: Source IP address of actor
 * - actor: String (or object?) of actor used to link events
 * - account_id: Unique account ID to give more context
 * - region/location: Region within the account to give more context
 * Additional fields:
 * - Any named fields the query author wants to add for more context
 */

/*
locals {
  cloudtrail_log_common_tags = merge(local.aws_common_tags, {
    service = "AWS/CloudTrail"
  })
}

// For detections, they should be able to:
// - Show OK/green if there are 0 items
// - Expand the full row info (based on tp_id/log_id) easily
// - Sort and filter by timestamp
// - Filter based on additional fields
// - Easily show events by the same actor for that session (or in the last hour)
// - Through vars (or something in the UI ad hoc), filter events out to reduce false positives
detection_list "cloudtrail_log_checks" {
  title       = "CloudTrail Log Checks"
  description = "This detection list contains recommendations when scanning CloudTrail logs."
  children = [
    detection.cloudtrail_log_iam_root_console_logins,
    detection.cloudtrail_log_iam_root_console_failed_logins,
  ]

  tags = merge(local.cloudtrail_log_common_tags, {
    type = "Detection List"
  })
}

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

  # Don't include MITRE info here since different versions can have different IDs
  tags = merge(local.cloudtrail_log_common_tags, {
    category = ""
  })
}

query "cloudtrail_log_iam_root_console_logins_test" {
  sql = <<-EOQ
    install json;
    load json;
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

detection "cloudtrail_log_iam_root_console_failed_logins" {
  title       = "IAM Root Failed Console Logins in CloudTrail Logs"
  description = "Detect failed IAM root user console logins to check for brute force attacks or use of old credentials."
  severity    = "high"
  query       = query.cloudtrail_log_iam_root_console_failed_logins_test
  author      = "cbruno"

  references  = [
    "https://docs.panther.com/alerts/alert-runbooks/built-in-rules/aws-console-login-failed"
  ]

  # Don't include MITRE info here since different versions can have different IDs
  # TODO: Should detection types be a top level property, tag?
  # TODO: How should we categorize them?
  tags = merge(local.cloudtrail_log_common_tags, {
    type = "failed attack"
  })
}


query "cloudtrail_log_iam_root_console_failed_logins_test" {
  sql = <<-EOQ
    install json;
    load json;
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
