## Description

This detection identifies instances where the code of an AWS Lambda function is updated without publishing a new version. Publishing a new version after a code update ensures that the updated function is immutable, can be referenced explicitly, and integrates seamlessly into workflows requiring version control. Skipping the publish step may lead to inconsistencies and potential deployment issues.

## Risks

Updating Lambda function code without publishing a new version can introduce deployment risks, as it may be unclear which code version is currently deployed or invoked. This can lead to inconsistencies, especially in environments with multiple consumers or automation systems referencing specific function versions.

In addition, skipping version publishing may impact debugging, rollback processes, and compliance requirements that necessitate clear version tracking of deployed code. Enforcing the publishing of new versions after updates ensures traceability, immutability, and stability in Lambda-based applications.

## References

- [Managing AWS Lambda Function Versions](https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html)
- [AWS CLI Command: update-function-code](https://docs.aws.amazon.com/cli/latest/reference/lambda/update-function-code.html)
- [AWS CLI Command: publish-version](https://docs.aws.amazon.com/cli/latest/reference/lambda/publish-version.html)
