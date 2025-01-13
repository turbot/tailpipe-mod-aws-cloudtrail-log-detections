## Description

This detection identifies the creation of IAM access keys. Access keys provide programmatic access to AWS services and resources, and their creation should be closely monitored to detect unauthorized activity or ensure compliance with security best practices.

## Risks

The creation of IAM access keys introduces potential security risks if not properly managed or monitored. Access keys can be exposed in various ways, such as being hardcoded into source code, accidentally shared publicly, or left unused for extended periods. If an access key is compromised, it could enable attackers to perform unauthorized actions, such as modifying resources, exfiltrating data, or launching further attacks.

Monitoring access key creation is critical to prevent unauthorized or unnecessary keys from being generated, especially for privileged accounts. It also helps enforce security best practices, such as rotating keys regularly, restricting their usage to specific resources, and ensuring that Multi-Factor Authentication (MFA) is enabled for associated accounts.

## References

- [AWS Documentation: Managing Access Keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)
- [AWS CLI Command: create-access-key](https://docs.aws.amazon.com/cli/latest/reference/iam/create-access-key.html)
- [AWS Documentation: Best Practices for Managing AWS Access Keys](https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html)
