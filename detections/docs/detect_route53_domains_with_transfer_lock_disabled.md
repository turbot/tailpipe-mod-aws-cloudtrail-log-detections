## Description

This detection identifies Route 53 domains where the transfer lock is disabled. The transfer lock is a critical security feature that prevents unauthorized domain transfers to another registrar or AWS account. Disabling the transfer lock increases the risk of losing control over your domain.

## Risks

When the transfer lock is disabled, a domain can be transferred to another registrar or account without additional authorization. This increases the risk of unauthorized transfers, potentially leading to loss of domain ownership, service disruptions, phishing attacks, or reputational damage.

Ensuring the transfer lock is enabled adds an extra layer of protection, preventing accidental or malicious domain transfers. Regular monitoring of transfer lock status helps maintain control over domains and ensures alignment with security best practices.

## References

- [Enabling Domain Transfer Lock](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-lock.html)
- [AWS CLI Command: enable-domain-transfer-lock](https://docs.aws.amazon.com/cli/latest/reference/route53domains/enable-domain-transfer-lock.html)
- [AWS CLI Command: disable-domain-transfer-lock](https://docs.aws.amazon.com/cli/latest/reference/route53domains/disable-domain-transfer-lock.html)
