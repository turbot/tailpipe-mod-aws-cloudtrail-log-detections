## Overview

Detect when an AWS Lambda function was created with function code encryption at rest disabled. Unencrypted code exposes sensitive business logic, secrets, or intellectual property to unauthorized access, increasing the risk of data breaches or malicious activity. Encrypting Lambda code ensures security, compliance, and protection against unauthorized access.

**References**:
- [Encrypting Lambda Function Code](https://docs.aws.amazon.com/lambda/latest/dg/security-encryption.html)
- [AWS CLI Command: update-function-code](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/lambda/update-function-code.html)
