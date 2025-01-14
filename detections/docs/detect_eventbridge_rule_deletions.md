## Description

This detection identifies deletions of Amazon EventBridge rules. EventBridge rules are used to route events to target services based on defined patterns. Deleting a rule without proper authorization or oversight can disrupt event-driven workflows and critical automation processes.

## Risks

Deleting EventBridge rules can interrupt the flow of events to their intended targets, such as AWS Lambda functions, SQS queues, or other services. This may result in disrupted workflows, delayed processing, or failure to trigger critical actions, potentially impacting application performance and business operations.

Unauthorized or accidental rule deletions may also indicate mismanagement or malicious activity, where an attacker seeks to disable monitoring, automation, or alerting mechanisms. Monitoring EventBridge rule deletions is essential to maintaining operational continuity and safeguarding event-driven systems.

## References

- [Amazon EventBridge Rules](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rules.html)
- [AWS CLI Command: delete-rule](https://docs.aws.amazon.com/cli/latest/reference/eventbridge/delete-rule.html)
