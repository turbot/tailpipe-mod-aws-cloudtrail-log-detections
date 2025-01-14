## Description

This detection identifies API Gateways that are configured to allow unrestricted public access. API Gateways are often used to expose backend services, and granting public access without proper security controls can expose sensitive resources to unauthorized users and malicious actors.

## Risks

Granting public access to an API Gateway introduces significant security risks. Without proper access controls, anyone on the internet can access the exposed APIs, potentially leading to data breaches, unauthorized operations, or abuse of the API. This is especially critical for APIs that allow write or administrative operations.

Overly permissive access settings may also indicate mismanagement or a lack of adherence to security best practices. An attacker could exploit publicly accessible API endpoints to perform attacks such as injection, brute force, or data exfiltration. To mitigate these risks, API Gateways should be configured with appropriate access controls, such as authorization mechanisms, rate limiting, and IP whitelisting.

## References

- [Amazon API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html)
- [Securing Amazon API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/security.html)
- [AWS CLI Command: get-rest-apis](https://docs.aws.amazon.com/cli/latest/reference/apigateway/get-rest-apis.html)
- [AWS Documentation: Best Practices for Securing APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-best-practices.html)
