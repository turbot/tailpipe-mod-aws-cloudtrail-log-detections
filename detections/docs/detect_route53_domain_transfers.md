## Description

This detection identifies instances where Route 53 domains are transferred to another registrar or AWS account. Monitoring domain transfers is critical to ensuring that domains remain secure and under authorized control. Unauthorized transfers could lead to service disruptions, phishing attacks, or loss of control over your web presence.

## Risks

Transferring a domain without proper authorization can expose your organization to security and operational risks. An unauthorized domain transfer could allow attackers to redirect traffic, launch phishing attacks, or disrupt services associated with the domain. Additionally, a loss of control over the domain could lead to reputational damage and regulatory non-compliance.

Regular monitoring of domain transfer activities ensures that only authorized transfers occur and that domains remain securely managed within trusted registrars or accounts.

## References

- [Transfer a Domain to Another AWS Account](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-transfer.html)
- [AWS Documentation: Transfer a Domain to Another Registrar](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-transfer-to-route-53.html)
- [AWS CLI Command: transfer-domain](https://docs.aws.amazon.com/cli/latest/reference/route53domains/transfer-domain.html)
