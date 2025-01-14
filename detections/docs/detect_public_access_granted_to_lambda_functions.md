## Description

This detection identifies AWS Lambda functions that are configured to allow public access. Lambda functions should be restricted to specific trusted users, roles, or services to prevent unauthorized execution and potential security risks. Publicly accessible Lambda functions can expose critical workloads to malicious actors.

## Risks

Granting public access to Lambda functions can result in unauthorized invocation, allowing attackers to exploit the function for malicious purposes. This could include overloading the function with excessive invocations, injecting malicious input, or gaining access to sensitive data and environments through the function's execution context.

Additionally, public access may lead to resource abuse, such as attackers using the Lambda function for unauthorized workloads, increasing AWS costs. Ensuring that Lambda functions are properly secured with permissions scoped to trusted entities is essential for maintaining a secure and cost-efficient environment.

## References

- [Lambda Permissions Model](https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html)
- [Best Practices for Securing Lambda Functions](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html)
- [AWS CLI Command: add-permission](https://docs.aws.amazon.com/cli/latest/reference/lambda/add-permission.html)
