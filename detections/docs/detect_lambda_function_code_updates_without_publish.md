## Overview

Detect updates to the code of an AWS Lambda function without publishing a new version. Skipping the publish step can cause inconsistencies, complicate version control, and impact debugging or rollback processes. Publishing new versions after updates ensures traceability, immutability, and stability in Lambda-based applications.

**References**:
- [Managing AWS Lambda Function Versions](https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html)
- [AWS CLI Command: update-function-code](https://docs.aws.amazon.com/cli/latest/reference/lambda/update-function-code.html)
- [AWS CLI Command: publish-version](https://docs.aws.amazon.com/cli/latest/reference/lambda/publish-version.html)
