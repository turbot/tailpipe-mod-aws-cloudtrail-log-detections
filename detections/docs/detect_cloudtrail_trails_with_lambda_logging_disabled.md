## Description

This detection identifies AWS CloudTrail trails where logging for AWS Lambda operations is disabled. CloudTrail can capture API calls made to Lambda, providing visibility into functions' creation, modification, invocation, and other management activities. Disabling Lambda logging reduces visibility into these critical operations, potentially hindering security monitoring and troubleshooting.

## Risks

Disabling Lambda logging on a CloudTrail trail can prevent the detection of unauthorized or unintended activity involving Lambda functions. This includes changes to function configurations, unauthorized invocations, or the deployment of malicious code. Without these logs, identifying and investigating security incidents becomes significantly more challenging.

In addition, Lambda logging is essential for auditing and compliance purposes. The absence of logs for Lambda operations can result in gaps in forensic data, making it difficult to ensure compliance with standards such as PCI DSS, ISO 27001, and SOC 2. Enabling Lambda logging ensures comprehensive monitoring and strengthens overall security and operational integrity.

## References

- [AWS Documentation: Logging AWS Lambda API Calls with CloudTrail](https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html)
- [AWS CLI Command: update-trail](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/update-trail.html)
