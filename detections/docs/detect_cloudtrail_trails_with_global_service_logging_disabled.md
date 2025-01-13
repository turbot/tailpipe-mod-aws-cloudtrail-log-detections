## Description

This detection identifies AWS CloudTrail trails that have global service event logging disabled. CloudTrail can log events for global services such as AWS Identity and Access Management (IAM), AWS Security Token Service (STS), and Amazon CloudFront. Disabling global service logging reduces visibility into critical account activities and may hinder security monitoring.

## Risks

Disabling global service logging on a CloudTrail trail can result in the loss of important event data related to global services. This includes actions such as authentication attempts, access key usage, and changes to IAM policies. Without this data, organizations may miss detecting unauthorized access, privilege escalation, or configuration changes that could compromise account security.

Additionally, global service logging is essential for compliance with many regulatory frameworks and security best practices. The absence of logs for global services can lead to non-compliance with standards such as PCI DSS, ISO 27001, and SOC 2. Ensuring global service event logging is enabled provides complete visibility into account activities and strengthens the security posture.

## References

- [AWS Documentation: Logging Global Service Events](https://jayendrapatil.com/aws-global-vs-regional-vs-az-resources/?utm_content=cmp-true#google_vignette)
- [AWS CLI Command: put-event-selectors](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/put-event-selectors.html)
