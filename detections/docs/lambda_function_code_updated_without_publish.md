## Overview

Detect when an AWS Lambda function code was updated without publishing a new version. Skipping the publish step can cause inconsistencies, complicate version control, and impact debugging or rollback processes. Publishing new versions after updates ensures traceability, immutability, and stability in Lambda-based applications.

**References**:
- [Managing AWS Lambda Function Versions](https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html)
- [AWS CLI Command: update-function-code](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/lambda/update-function-code.html)
- [AWS CLI Command: publish-version](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/lambda/publish-version.html)
