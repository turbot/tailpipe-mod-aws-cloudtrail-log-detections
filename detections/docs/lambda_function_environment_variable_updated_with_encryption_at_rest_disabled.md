## Overview

Detect when an AWS Lambda function environment variable was updated with encryption at rest disabled. Unencrypted environment variables expose sensitive data, such as credentials or API keys, to potential compromise, increasing the risk of unauthorized access or privilege escalation. Encrypting environment variables using AWS Key Management Service (KMS) ensures data security and compliance with industry standards.

**References**:
- [Lambda Function Environment Variables](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html)
- [Encrypting Environment Variables](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html#configuration-envvars-encryption)
- [AWS CLI Command: update-function-configuration](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/lambda/update-function-configuration.html)
