## Description

This detection identifies AWS Lambda functions that use unencrypted environment variables. Environment variables in Lambda functions often store sensitive information, such as database credentials, API keys, or other configuration details. Ensuring these variables are encrypted protects them from unauthorized access and reduces the risk of data breaches.

## Risks

Using unencrypted environment variables in Lambda functions exposes sensitive data to potential compromise. An attacker who gains access to the function configuration could extract secrets, credentials, or other sensitive information, which could then be used to access critical resources or escalate privileges.

Failing to encrypt environment variables also increases the likelihood of non-compliance with regulatory requirements and industry standards, such as PCI DSS, GDPR, or HIPAA. Encrypting environment variables using AWS Key Management Service (KMS) ensures that sensitive information remains secure and protected against unauthorized access.

## References

- [LAmbda Function Environment Variables](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html)
- [Encrypting Environment Variables](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html#configuration-envvars-encryption)
- [AWS CLI Command: update-function-configuration](https://docs.aws.amazon.com/cli/latest/reference/lambda/update-function-configuration.html)
