## Overview

Detect when AWS Secrets Manager fails to rotate a secret. Secret rotation is a critical security practice that helps limit the impact of credential compromise and maintain compliance with security policies.

Rotation failures can occur due to:
- Lambda rotation function errors or timeouts
- Permission issues with the rotation Lambda function
- Invalid configuration of the secret or its rotation settings
- Backend service issues preventing credential updates
- Network connectivity problems

Failed rotations may leave systems using outdated credentials, which could result in:
- Extended use of potentially compromised credentials
- Service disruptions when credentials eventually expire
- Compliance violations for organizations requiring regular credential rotation
- Increased risk of lateral movement if credentials are compromised

**References**:
- [AWS Secrets Manager Rotation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html)
- [Troubleshooting Secret Rotation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/troubleshoot_rotation.html)
- [Automated Rotation for AWS Secrets Manager](https://aws.amazon.com/blogs/security/how-to-use-aws-secrets-manager-securely-store-rotate-database-credentials/)
