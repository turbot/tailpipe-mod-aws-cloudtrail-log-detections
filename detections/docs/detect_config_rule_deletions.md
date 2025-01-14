## Description

This detection identifies instances where AWS Config rules are deleted. AWS Config rules help monitor compliance by evaluating AWS resource configurations against defined policies. Deleting a Config rule can disrupt compliance monitoring and reduce visibility into configuration changes.

## Risks

Deleting a Config rule disables the evaluation of associated resource configurations, potentially allowing non-compliant resources to remain undetected. This can lead to security risks, operational inefficiencies, or violations of internal and regulatory compliance requirements.

Unauthorized or accidental deletions of Config rules may indicate malicious activity, such as an attempt to suppress compliance monitoring, or mismanagement of critical monitoring configurations. Monitoring Config rule deletions ensures continuous evaluation of resource compliance and helps maintain a secure and compliant cloud environment.

## References

- [AWS Config Rules](https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config.html)
- [AWS CLI Command: delete-config-rule](https://docs.aws.amazon.com/cli/latest/reference/configservice/delete-config-rule.html)
