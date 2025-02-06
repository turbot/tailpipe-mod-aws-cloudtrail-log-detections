## v0.2.0 [2025-02-06]

_Enhancements_

- Add documentation for `activity_dashboard` and `root_user_activity_report` dashboards. ([#9](https://github.com/turbot/tailpipe-mod-aws-cloudtrail-log-detections/pull/9))

## v0.1.0 [2025-01-30]

_What's new?_

- New benchmarks added:
  - CloudTrail Log Detections benchmark (`powerpipe benchmark run aws_cloudtrail_log_detections.benchmark.cloudtrail_log_detections`).
  - MITRE ATT&CK v16.1 benchmark (`powerpipe benchmark run aws_cloudtrail_log_detections.benchmark.mitre_attack_v161`).
  
- New dashboards added:
  - [CloudTrail Log Activity Dashboard](https://hub.powerpipe.io/mods/turbot/aws_cloudtrail_log_detections/dashboards/dashboard.activity_dashboard)
  - [CloudTrail Log Root User Activity Report](https://hub.powerpipe.io/mods/turbot/aws_cloudtrail_log_detections/dashboards/dashboard.root_user_activity_report)