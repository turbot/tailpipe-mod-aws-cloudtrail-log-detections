## Description

This detection identifies AWS Lambda functions that use unencrypted code. Lambda function code should be encrypted to ensure that sensitive business logic, secrets, or intellectual property embedded within the code is protected from unauthorized access and tampering.

## Risks

Using unencrypted code for Lambda functions exposes sensitive information within the function to potential compromise. An attacker who gains unauthorized access to the code could extract sensitive business logic, credentials, or other embedded secrets, potentially leading to data breaches or unauthorized activity.

Additionally, unencrypted Lambda code may fail to meet regulatory and security compliance requirements, such as PCI DSS, HIPAA, or GDPR, which mandate secure storage of sensitive data. Encrypting Lambda code using AWS Key Management Service (KMS) or other encryption mechanisms ensures that code remains secure and protected against unauthorized access.

## References

- [Encrypting Lambda Function Code](https://docs.aws.amazon.com/lambda/latest/dg/security-encryption.html)
- [AWS CLI Command: update-function-code](https://docs.aws.amazon.com/cli/latest/reference/lambda/update-function-code.html)
