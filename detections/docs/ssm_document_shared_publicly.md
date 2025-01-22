## Overview

Detect when an AWS Systems Manager (SSM) document was shared publicly. Publicly accessible SSM documents can expose sensitive configurations, scripts, or automation tasks to unauthorized users. Ensuring documents are private or shared only with trusted entities helps protect sensitive information and maintain secure access controls.

**References**:
- [AWS Systems Manager Documents](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-ssm-docs.html)
- [Best Practices for AWS Systems Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/best-practices.html)
- [AWS CLI Command: modify-document-permission](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ssm/modify-document-permission.html)