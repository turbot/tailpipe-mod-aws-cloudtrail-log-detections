## Description

This detection identifies Amazon EventBridge rules that have been disabled. EventBridge rules are critical for routing events to target services based on predefined patterns. Disabling a rule can disrupt event-driven workflows and prevent automated actions from being triggered as expected.

## Risks

Disabling an EventBridge rule can interrupt the delivery of events to their intended targets, such as AWS Lambda functions, SQS queues, or other services. This may result in delayed processing, missed alerts, or failure to execute critical actions, impacting application functionality and operational efficiency.

Unauthorized or accidental disabling of rules may indicate mismanagement or malicious activity, such as an attacker attempting to suppress event-driven monitoring, alerting, or automation mechanisms. Monitoring the status of EventBridge rules ensures that critical workflows remain operational and that any changes are authorized and intentional.

## References

- [Amazon EventBridge Rules](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rules.html)
- [AWS CLI Command: disable-rule](https://docs.aws.amazon.com/cli/latest/reference/eventbridge/disable-rule.html)
