## Description

This detection identifies changes to the threshold values of Amazon CloudWatch alarms. CloudWatch alarms are used to monitor metrics and trigger actions based on defined thresholds. Modifying alarm thresholds without proper authorization can reduce the effectiveness of monitoring and lead to undetected issues.

## Risks

Changing CloudWatch alarm thresholds can result in critical events being missed or false alarms being generated. For example, increasing a threshold may delay detection of performance issues, security incidents, or resource exhaustion, while decreasing it may cause unnecessary alerts, leading to alert fatigue.

Unauthorized or accidental modifications to alarm thresholds may indicate mismanagement or malicious activity. An attacker could modify thresholds to suppress alarms and hide their actions, compromising the security and availability of resources. Regular monitoring of threshold changes ensures the integrity of alarm configurations and maintains the effectiveness of operational monitoring.

## References

- [Using CloudWatch Alarms](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html)
- [AWS CLI Command: describe-alarms](https://docs.aws.amazon.com/cli/latest/reference/cloudwatch/describe-alarms.html)
